/* for testing purpose */

#include "ckb_smt.h"
#include "ckb_sst.h"
#include "ckb_syscalls.h"

#define TEMP_SIZE 32768

/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65

/* secp256k1 unlock errors */
#define ERROR_ARGUMENTS_LEN -1
#define ERROR_ENCODING -2
#define ERROR_SYSCALL -3
#define ERROR_SECP_RECOVER_PUBKEY -11
#define ERROR_SECP_VERIFICATION -12
#define ERROR_SECP_PARSE_PUBKEY -13
#define ERROR_SECP_PARSE_SIGNATURE -14
#define ERROR_SECP_SERIALIZE_PUBKEY -15
#define ERROR_SCRIPT_TOO_LONG -21
#define ERROR_WITNESS_SIZE -22
#define ERROR_INCORRECT_SINCE_FLAGS -23
#define ERROR_INCORRECT_SINCE_VALUE -24
#define ERROR_PUBKEY_BLAKE160_HASH -31

#if (MAX_WITNESS_SIZE > TEMP_SIZE) || (SCRIPT_SIZE > TEMP_SIZE)
#error "Temp buffer is not big enough!"
#endif

/* Extract input_type from WitnessArgs */
int extract_witness_input_type(uint8_t *witness_bytes, uint64_t *witness_len,
                               mol_seg_t *proof_seg, mol_seg_t *updates_seg) {
  int ret;
  /* Load witness of first input */
  *witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness_bytes, witness_len, 0, 0,
                         CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (*witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  mol_seg_t witness_seg;
  witness_seg.ptr = witness_bytes;
  witness_seg.size = *witness_len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t input_type_seg = MolReader_WitnessArgs_get_input_type(&witness_seg);

  if (MolReader_BytesOpt_is_none(&input_type_seg)) {
    return ERROR_ENCODING;
  }
  mol_seg_t input_type_bytes_seg = MolReader_Bytes_raw_bytes(&input_type_seg);

  // load proof data
  *proof_seg = MolReader_SmtUpdateAction_get_proof(&input_type_bytes_seg);
  *updates_seg = MolReader_SmtUpdateAction_get_updates(&input_type_bytes_seg);

  return CKB_SUCCESS;
}

int load_proof_from_cell_data(uint8_t *proof, size_t source) {
  int ret;

  unsigned char data[MAX_WITNESS_SIZE];
  uint64_t len = MAX_WITNESS_SIZE;

  ret = ckb_checked_load_cell_data(data, &len, 0, 0, source);
  // printf("len %d",(int)len);

  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  mol_seg_t data_seg;
  data_seg.ptr = data;
  data_seg.size = len;

  if (MolReader_SSTData_verify(&data_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t smt_root_seg = MolReader_SSTData_get_smt_root(&data_seg);
  memcpy(proof, smt_root_seg.ptr, smt_root_seg.size);

  return CKB_SUCCESS;
}

int blake2b_value(uint8_t *msg, mol_seg_t *value_seg) {
  mol_seg_t amount_seg = MolReader_AccountValue_get_amount(value_seg);
  mol_seg_t nonce_seg = MolReader_AccountValue_get_nonce(value_seg);
  mol_seg_t timestamp_seg = MolReader_AccountValue_get_timestamp(value_seg);

  /* Prepare sign message */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, 32);

  blake2b_update(&blake2b_ctx, amount_seg.ptr, amount_seg.size);
  blake2b_update(&blake2b_ctx, nonce_seg.ptr, nonce_seg.size);
  blake2b_update(&blake2b_ctx, timestamp_seg.ptr, timestamp_seg.size);

  blake2b_final(&blake2b_ctx, msg, 32);
  return CKB_SUCCESS;
}

__attribute__((visibility("default"))) int validate_smt() {
  // load witnesses

  int ret;
  uint8_t old_root[32];
  uint8_t new_root[32];

  ret = load_proof_from_cell_data(old_root, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    // printf("load input data failed");
    return ret;
  }
  ret = load_proof_from_cell_data(new_root, CKB_SOURCE_GROUP_OUTPUT);
  if (ret != CKB_SUCCESS) {
    // printf("load output data failed");
    return ret;
  }

  // get proof from witness
  smt_pair_t old_leaves[1024];
  smt_pair_t new_leaves[1024];

  smt_state_t old_state;
  smt_state_init(&old_state, old_leaves, 1024);

  smt_state_t new_state;
  smt_state_init(&new_state, new_leaves, 1024);

  // get leaves from witness
  // node = (key, old_value, new_value);
  mol_seg_t proof_seg, updates_seg;

  /* try load signature */
  unsigned char first_witness[MAX_WITNESS_SIZE];
  uint64_t first_witness_len = 0;
  ret = extract_witness_input_type(first_witness, &first_witness_len,
                                   &proof_seg, &updates_seg);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  // printf("finish load witness input_type");

  mol_num_t updates_size = MolReader_SmtUpdateItemVec_length(&updates_seg);
  for (int i = 0; i < updates_size; i++) {
    mol_seg_res_t update_item_res_seg =
        MolReader_SmtUpdateItemVec_get(&updates_seg, i);
    if (update_item_res_seg.errno != MOL_OK) {
      break;
    }

    mol_seg_t key_seg =
        MolReader_SmtUpdateItem_get_key(&update_item_res_seg.seg);
    mol_seg_t old_value_seg =
        MolReader_SmtUpdateItem_get_old_value(&update_item_res_seg.seg);
    mol_seg_t new_value_seg =
        MolReader_SmtUpdateItem_get_new_value(&update_item_res_seg.seg);

    // blake2b value
    unsigned char old_msg[32];
    blake2b_value(old_msg, &old_value_seg);
    smt_state_insert(&old_state, key_seg.ptr, old_msg);

    unsigned char new_msg[32];
    blake2b_value(new_msg, &new_value_seg);
    smt_state_insert(&new_state, key_seg.ptr, new_msg);
  }

  smt_state_normalize(&old_state);
  smt_state_normalize(&new_state);

  mol_seg_t raw_proof_seg = MolReader_SmtProof_raw_bytes(&proof_seg);

  int ret1 = smt_verify((const uint8_t *)old_root, &old_state,
                        raw_proof_seg.ptr, raw_proof_seg.size);
  if (ret1 != 0) {
    printf("ret1 = %d", ret1);
    return ret1;
  }

  int ret2 = smt_verify((const uint8_t *)new_root, &new_state,
                        raw_proof_seg.ptr, raw_proof_seg.size);
  printf("ret2 = %d", ret2);
  return ret2;
}


int main() { 
  return validate_smt(); 
  }
