#include <stdio.h>
#include <libdwarf-0/dwarf.h>
#include <libdwarf-0/libdwarf.h>
#include <cstdlib>
#include <stdint.h>

int main()
{
  Dwarf_Debug dw_dbg = 0;
  Dwarf_Error dw_err = 0;
  char* buf_name = (char *)malloc(100 * sizeof(char));
  buf_name[0] = '\0';
  int res;

  //Dwarf_Off die_offset = 0X1cd; // fiveBySixMatrix DIE offset (from DWARF debug_info)
  Dwarf_Off die_func_id = 0X451; // myFunction DIE offset (from DWARF debug_info)

  res = dwarf_init_path("/home/mgiampaolo/Desktop/tesis/prueba/dwarfeame_vector", buf_name, 100, DW_GROUPNUMBER_ANY, nullptr, nullptr, &dw_dbg, &dw_err);

  printf("dwarf init path res: %d \n", res);

  printf("buf name: %s \n", buf_name);

  Dwarf_Die my_precious_die;
  res = dwarf_offdie_b(dw_dbg, die_func_id, true, &my_precious_die, &dw_err);
  printf("dwarf offset die segun file: %d \n", res);

  char* die_name = (char *)malloc(100 * sizeof(char));
  res = dwarf_diename(my_precious_die, &die_name, &dw_err);
  printf("dwarf DIE name: %d - DIE NAME: %s\n", res, die_name);
  Dwarf_Addr addr;

  res = dwarf_lowpc(my_precious_die, &addr, &dw_err);
  printf("dw err: %d \n", dw_err);
  printf("dwarf DIE low PC res: %d\n DIE low program counter address: 0x%X \n", res, addr);

  //Dwarf_Attribute attr;
  //res = dwarf_attr(my_precious_die, DW_AT_linkage_name, &attr, &dw_err);
  //printf("dwarf attr err: %d \n", dw_err);

  char* linkageName = (char *)malloc(100 * sizeof(char));
  res = dwarf_die_text(my_precious_die, DW_AT_linkage_name, &linkageName, &dw_err);
  printf("dwarf die text err: %d \n", dw_err);
  printf("dwarf die text err:%d - string %s\n", res, linkageName);

  ////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////
  Dwarf_Off die_var_id = 0X4a5;

  Dwarf_Die my_var_die;
  res = dwarf_offdie_b(dw_dbg, die_var_id, true, &my_var_die, &dw_err);
  printf("dwarf read my var: %d \n", res);

  Dwarf_Half dwarf_version;
  Dwarf_Half address_size;
  Dwarf_Half offset_size;
  res = dwarf_cu_header_basics(
    my_var_die, &dwarf_version,
    NULL, NULL, 
    &offset_size, &address_size,
    NULL, NULL, NULL, NULL, 
    &dw_err
    );

  printf("dwarf header basics res: %d - DIE offset size: %d - DIE address size: %d - DWARF Version:%d \n", res, offset_size, address_size, dwarf_version);

  char* var_die_name = (char *)malloc(100 * sizeof(char));
  res = dwarf_diename(my_var_die, &var_die_name, &dw_err);
  printf("dwarf DIE name: %d - DIE NAME: %s\n", res, var_die_name);

  Dwarf_Attribute attr;
  res = dwarf_attr(my_var_die, DW_AT_location, &attr, &dw_err);
  printf("dwarf attr: res:%d - err: %d \n", res, dw_err);

  Dwarf_Unsigned exprlen;
  Dwarf_Ptr ptr;
  res = dwarf_formexprloc(attr, &exprlen, &ptr, &dw_err);
  printf("addr die res: %d \n", res);
  printf("addr die err: %d \n", dw_err);
  printf("exprlen: %lu \n", exprlen);

  // Dwarf_Half var_die_size;
  // dwarf_get_die_address_size(my_var_die, &var_die_size, &dw_err);
  
  Dwarf_Loc_Head_c lochead;
  Dwarf_Unsigned listlen = 0;
  res = dwarf_loclist_from_expr_c(
    dw_dbg, 
    ptr, 
    exprlen,
    address_size,
    offset_size,
    dwarf_version,
    &lochead,
    &listlen,
    &dw_err
    );
  printf("dwarf Loclist from expr res: %d - Dwarf expr listlen: %d\n", res, listlen);

  //Dwarf_Loc_Head_c expr_loc = ptr;
  //printf("addr die: res %d - err %d -  %lu\n", res, dw_err, var_addr);
  //printf("addr die: res %d - err %d -  %s\n", res, dw_err, var_addr);
  //dwarf_loclist_from_expr_c();

  Dwarf_Bool debug_addr_unavaialable;
  //Dwarf_Unsigned loc_index;
 // Dwarf_Unsigned dw_expression_offset_out;
 // Dwarf_Unsigned dw_locdesc_offset_out;
    Dwarf_Locdesc_c  locentry = 0;
    Dwarf_Unsigned rawlopc = 0;
    Dwarf_Unsigned rawhipc = 0;
    Dwarf_Bool     debug_addr_unavail;
    Dwarf_Unsigned lopc = 0;
    Dwarf_Unsigned hipc = 0;
    Dwarf_Unsigned ulocentry_count = 0;
    Dwarf_Unsigned section_offset = 0;
    Dwarf_Unsigned locdesc_offset = 0;
    Dwarf_Small    lle_value = 0;
    Dwarf_Small    loclist_source = 0;


  Dwarf_Locdesc_c locdesc;
  res = dwarf_get_locdesc_entry_d(
      lochead,
      0,
      &lle_value,
      &rawlopc, &rawhipc, &debug_addr_unavail, &lopc, &hipc,
      &ulocentry_count, &locentry,
      &loclist_source, &section_offset, &locdesc_offset,
      &dw_err // dw_error
  );
  printf("get locdesc res: %d\n", res);
  printf("ulocentry count: %d\n", ulocentry_count);
  printf("get locdesc res: %d - dw_expression_offset_out: %lu - dw_locdesc_offset_out: %lu\n", res, section_offset, locdesc_offset);
  Dwarf_Small op = 0;
  Dwarf_Unsigned opd1 = 0;
  Dwarf_Unsigned opd2 = 0;
  Dwarf_Unsigned opd3 = 0;
  Dwarf_Unsigned offsetforbranch = 0;

  res = dwarf_get_location_op_value_c(locentry,
                                    0, &op, &opd1, &opd2, &opd3,
                                    &offsetforbranch,
                                    &dw_err);

  printf("get ops res: %d\n", res);
  printf("op: %lu\n", op);
  printf("op1: %lu\n", opd1);
  printf("op2: %lu\n", opd2);
  printf("op3: %lu\n", opd3);
  printf("offset branch: %lu\n", offsetforbranch);

  Dwarf_Unsigned dw_leblen;
  Dwarf_Signed dw_outval;
  char endptr;
  res = dwarf_decode_signed_leb128((char*)opd1, &dw_leblen, &dw_outval, &endptr);
  printf("res: %d\n", res);
  printf("leblen: %lu\n", dw_leblen);
  printf("outval: %lu\n", dw_outval);
  printf("endptr: %s\n", endptr);


  free(buf_name);
  // free(die_name);
  dwarf_finish(dw_dbg);

  return 0;
}

int64_t decode_signed_leb128(const uint8_t *data, size_t *offset) {
    int64_t result = 0;
    uint8_t byte;
    int shift = 0;

    do {
        byte = data[*offset];
        result |= (int64_t)(byte & 0x7f) << shift;
        shift += 7;
        (*offset)++;
    } while (byte & 0x80); // Continue while the MSB is 1

    // Sign extend if necessary
    if (shift < 64 && (byte & 0x40)) {
        result |= -(1L << shift);
    }

    return result;
}