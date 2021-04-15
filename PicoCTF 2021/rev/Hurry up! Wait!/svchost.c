typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef unsigned long    qword;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long    undefined8;
typedef unsigned short    word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;

struct eh_frame_hdr {
    byte eh_frame_hdr_version; // Exception Handler Frame Header Version
    dwfenc eh_frame_pointer_encoding; // Exception Handler Frame Pointer Encoding
    dwfenc eh_frame_desc_entry_count_encoding; // Encoding of # of Exception Handler FDEs
    dwfenc eh_frame_table_encoding; // Exception Handler Table Encoding
};

typedef struct fde_table_entry fde_table_entry, *Pfde_table_entry;

struct fde_table_entry {
    dword initial_loc; // Initial Location
    dword data_loc; // Data location
};

typedef struct Elf64_Shdr Elf64_Shdr, *PElf64_Shdr;

typedef enum Elf_SectionHeaderType {
    SHT_CHECKSUM=1879048184,
    SHT_DYNAMIC=6,
    SHT_DYNSYM=11,
    SHT_FINI_ARRAY=15,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191,
    SHT_GROUP=17,
    SHT_HASH=5,
    SHT_INIT_ARRAY=14,
    SHT_NOBITS=8,
    SHT_NOTE=7,
    SHT_NULL=0,
    SHT_PREINIT_ARRAY=16,
    SHT_PROGBITS=1,
    SHT_REL=9,
    SHT_RELA=4,
    SHT_SHLIB=10,
    SHT_STRTAB=3,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_syminfo=1879048188,
    SHT_SYMTAB=2,
    SHT_SYMTAB_SHNDX=18
} Elf_SectionHeaderType;

struct Elf64_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType sh_type;
    qword sh_flags;
    qword sh_addr;
    qword sh_offset;
    qword sh_size;
    dword sh_link;
    dword sh_info;
    qword sh_addralign;
    qword sh_entsize;
};

typedef struct Elf64_Phdr Elf64_Phdr, *PElf64_Phdr;

typedef enum Elf_ProgramHeaderType {
    PT_DYNAMIC=2,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_RELRO=1685382482,
    PT_GNU_STACK=1685382481,
    PT_INTERP=3,
    PT_LOAD=1,
    PT_NOTE=4,
    PT_NULL=0,
    PT_PHDR=6,
    PT_SHLIB=5,
    PT_TLS=7
} Elf_ProgramHeaderType;

struct Elf64_Phdr {
    enum Elf_ProgramHeaderType p_type;
    dword p_flags;
    qword p_offset;
    qword p_vaddr;
    qword p_paddr;
    qword p_filesz;
    qword p_memsz;
    qword p_align;
};

typedef struct Elf64_Dyn Elf64_Dyn, *PElf64_Dyn;

typedef enum Elf64_DynTag {
    DT_AUDIT=1879047932,
    DT_AUXILIARY=2147483645,
    DT_BIND_NOW=24,
    DT_CHECKSUM=1879047672,
    DT_CONFIG=1879047930,
    DT_DEBUG=21,
    DT_DEPAUDIT=1879047931,
    DT_ENCODING=32,
    DT_FEATURE_1=1879047676,
    DT_FILTER=2147483647,
    DT_FINI=13,
    DT_FINI_ARRAY=26,
    DT_FINI_ARRAYSZ=28,
    DT_FLAGS=30,
    DT_FLAGS_1=1879048187,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_HASH=1879047925,
    DT_GNU_LIBLIST=1879047929,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_GNU_PRELINKED=1879047669,
    DT_HASH=4,
    DT_INIT=12,
    DT_INIT_ARRAY=25,
    DT_INIT_ARRAYSZ=27,
    DT_JMPREL=23,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_MOVETAB=1879047934,
    DT_NEEDED=1,
    DT_NULL=0,
    DT_PLTGOT=3,
    DT_PLTPAD=1879047933,
    DT_PLTPADSZ=1879047673,
    DT_PLTREL=20,
    DT_PLTRELSZ=2,
    DT_POSFLAG_1=1879047677,
    DT_PREINIT_ARRAYSZ=33,
    DT_REL=17,
    DT_RELA=7,
    DT_RELACOUNT=1879048185,
    DT_RELAENT=9,
    DT_RELASZ=8,
    DT_RELCOUNT=1879048186,
    DT_RELENT=19,
    DT_RELSZ=18,
    DT_RPATH=15,
    DT_RUNPATH=29,
    DT_SONAME=14,
    DT_STRSZ=10,
    DT_STRTAB=5,
    DT_SYMBOLIC=16,
    DT_SYMENT=11,
    DT_SYMINENT=1879047679,
    DT_SYMINFO=1879047935,
    DT_SYMINSZ=1879047678,
    DT_SYMTAB=6,
    DT_TEXTREL=22,
    DT_TLSDESC_GOT=1879047927,
    DT_TLSDESC_PLT=1879047926,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_VERSYM=1879048176
} Elf64_DynTag;

struct Elf64_Dyn {
    enum Elf64_DynTag d_tag;
    qword d_val;
};

typedef struct Elf64_Rela Elf64_Rela, *PElf64_Rela;

struct Elf64_Rela {
    qword r_offset; // location to apply the relocation action
    qword r_info; // the symbol table index and the type of relocation
    qword r_addend; // a constant addend used to compute the relocatable field value
};

typedef struct Elf64_Ehdr Elf64_Ehdr, *PElf64_Ehdr;

struct Elf64_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_pad[9];
    word e_type;
    word e_machine;
    dword e_version;
    qword e_entry;
    qword e_phoff;
    qword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};

typedef struct Elf64_Sym Elf64_Sym, *PElf64_Sym;

struct Elf64_Sym {
    dword st_name;
    byte st_info;
    byte st_other;
    word st_shndx;
    qword st_value;
    qword st_size;
};

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

struct evp_pkey_ctx_st {
};

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;




int _init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  iVar1 = __gmon_start__();
  return iVar1;
}



void interfaces__c___elabs(void)

{
  interfaces__c___elabs();
  return;
}



void system__finalization_root___elabs(void)

{
  system__finalization_root___elabs();
  return;
}



void __gnat_reraise_library_exception_if_any(void)

{
  __gnat_reraise_library_exception_if_any();
  return;
}



void ada__tags___elabb(void)

{
  ada__tags___elabb();
  return;
}



void __gnat_finalize(void)

{
  __gnat_finalize();
  return;
}



void system__os_lib___elabb(void)

{
  system__os_lib___elabb();
  return;
}



void system__secondary_stack___elabb(void)

{
  system__secondary_stack___elabb();
  return;
}



void system__soft_links___elabb(void)

{
  system__soft_links___elabb();
  return;
}



void ada__calendar___elabs(void)

{
  ada__calendar___elabs();
  return;
}



void ada__text_io___elabs(void)

{
  ada__text_io___elabs();
  return;
}



void system__exceptions___elabs(void)

{
  system__exceptions___elabs();
  return;
}



void system__exception_table___elabb(void)

{
  system__exception_table___elabb();
  return;
}



void system__standard_library__adafinal(void)

{
  system__standard_library__adafinal();
  return;
}



void ada__calendar___elabb(void)

{
  ada__calendar___elabb();
  return;
}



void __gnat_initialize(void)

{
  __gnat_initialize();
  return;
}



void __gnat_runtime_finalize(void)

{
  __gnat_runtime_finalize();
  return;
}



void ada__text_io___elabb(void)

{
  ada__text_io___elabb();
  return;
}



void system__soft_links___elabs(void)

{
  system__soft_links___elabs();
  return;
}



void ada__calendar__delays___elabb(void)

{
  ada__calendar__delays___elabb();
  return;
}



void system__file_io___elabb(void)

{
  system__file_io___elabb();
  return;
}



void ada__text_io__put__4(void)

{
  ada__text_io__put__4();
  return;
}



void ada__text_io__put_line__2(void)

{
  ada__text_io__put_line__2();
  return;
}



void ada__calendar__delays__delay_for(void)

{
  ada__calendar__delays__delay_for();
  return;
}



void system__file_io__finalize_body(void)

{
  system__file_io__finalize_body();
  return;
}



void ada__finalization___elabs(void)

{
  ada__finalization___elabs();
  return;
}



void ada__tags___elabs(void)

{
  ada__tags___elabs();
  return;
}



void ada__io_exceptions___elabs(void)

{
  ada__io_exceptions___elabs();
  return;
}



void ada__text_io__finalize_spec(void)

{
  ada__text_io__finalize_spec();
  return;
}



void ada__streams___elabs(void)

{
  ada__streams___elabs();
  return;
}



void __gnat_runtime_initialize(void)

{
  __gnat_runtime_initialize();
  return;
}



void system__file_control_block___elabs(void)

{
  system__file_control_block___elabs();
  return;
}



void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 in_stack_00000000;
  undefined auStack8 [8];
  
  __libc_start_main(main,in_stack_00000000,&stack0x00000008,&LAB_00102a30,&DAT_00102aa0,param_3,
                    auStack8);
  do {
                    // WARNING: Do nothing block with infinite loop
  } while( true );
}



// WARNING: Removing unreachable block (ram,0x00101c57)
// WARNING: Removing unreachable block (ram,0x00101c63)

void FUN_00101c40(void)

{
  return;
}



void _FINI_0(void)

{
  if (DAT_003041a2 != '\0') {
    return;
  }
  __cxa_finalize(PTR_LOOP_00304008);
  FUN_00101c40();
  DAT_003041a2 = 1;
  return;
}



// WARNING: Removing unreachable block (ram,0x00101ca8)
// WARNING: Removing unreachable block (ram,0x00101cb4)

void _INIT_0(void)

{
  return;
}



void FUN_00101d1a(void)

{
  ada__text_io_E = ada__text_io_E + -1;
  ada__text_io__finalize_spec();
  system__file_io_E = system__file_io_E + -1;
  system__file_io__finalize_body();
  __gnat_reraise_library_exception_if_any();
  return;
}



void FUN_00101d52(void)

{
  if (DAT_00304012 == '\x01') {
    DAT_00304012 = '\0';
    __gnat_runtime_finalize();
    system__standard_library__adafinal();
  }
  return;
}



void random_start_stuff(void)

{
  if (DAT_00304012 == '\0') {
    DAT_00304012 = '\x01';
    __gl_main_priority = 0xffffffff;
    __gl_time_slice_val = 0xffffffff;
    __gl_wc_encoding = 0x62;
    __gl_locking_policy = 0x20;
    __gl_queuing_policy = 0x20;
    __gl_task_dispatching_policy = 0x20;
    __gl_priority_specific_dispatching = &DAT_00102c54;
    __gl_num_specific_dispatching = 0;
    __gl_main_cpu = 0xffffffff;
    __gl_interrupt_states = &DAT_00102c55;
    __gl_num_interrupt_states = 0;
    __gl_unreserve_all_interrupts = 0;
    __gl_detect_blocking = 0;
    __gl_default_stack_size = 0xffffffff;
    __gl_leap_seconds_support = 0;
    __gnat_runtime_initialize(1);
    __gnat_finalize_library_objects = FUN_00101d1a;
    system__soft_links___elabs();
    system__exception_table___elabb();
    system__exception_table_E = system__exception_table_E + 1;
    system__exceptions___elabs();
    system__exceptions_E = system__exceptions_E + 1;
    system__soft_links___elabb();
    system__soft_links_E = system__soft_links_E + 1;
    system__secondary_stack___elabb();
    system__secondary_stack_E = system__secondary_stack_E + 1;
    ada__io_exceptions___elabs();
    ada__io_exceptions_E = ada__io_exceptions_E + 1;
    interfaces__c___elabs();
    interfaces__c_E = interfaces__c_E + 1;
    system__os_lib___elabb();
    system__os_lib_E = system__os_lib_E + 1;
    ada__tags___elabs();
    ada__tags___elabb();
    ada__tags_E = ada__tags_E + 1;
    ada__streams___elabs();
    ada__streams_E = ada__streams_E + 1;
    system__file_control_block___elabs();
    system__file_control_block_E = system__file_control_block_E + 1;
    system__finalization_root___elabs();
    system__finalization_root_E = system__finalization_root_E + 1;
    ada__finalization___elabs();
    ada__finalization_E = ada__finalization_E + 1;
    system__file_io___elabb();
    system__file_io_E = system__file_io_E + 1;
    ada__calendar___elabs();
    ada__calendar___elabb();
    ada__calendar_E = ada__calendar_E + 1;
    ada__calendar__delays___elabb();
    ada__calendar__delays_E = ada__calendar__delays_E + 1;
    ada__text_io___elabs();
    ada__text_io___elabb();
    ada__text_io_E = ada__text_io_E + 1;
    DAT_00304014 = DAT_00304014 + 1;
  }
  return;
}



int main(int argc,char **argv,undefined8 param_3)

{
  undefined local_10 [8];
  
  gnat_envp = param_3;
  gnat_argv = argv;
  gnat_argc = argc;
  __gnat_initialize(local_10);
  random_start_stuff();
  idk();
  FUN_00101d52();
  __gnat_finalize();
  return gnat_exit_status;
}



void FUN_00102032(void)

{
  ada__text_io__put_line__2(&DAT_00102c58,&DAT_00102c68,&DAT_00102c68,&DAT_00102c58);
  return;
}



void FUN_00102066(void)

{
  ada__text_io__put_line__2
            ("In \'send_secret_1\'",&DAT_00102c88,&DAT_00102c88,"In \'send_secret_1\'");
  return;
}



void FUN_0010209a(void)

{
  ada__text_io__put_line__2
            ("In \'send_secret_2\'In \'send_secret_3\'0",&DAT_00102c88,&DAT_00102c88,
             "In \'send_secret_2\'In \'send_secret_3\'0");
  return;
}



void FUN_001020ce(void)

{
  ada__text_io__put_line__2(0x102ca2,&DAT_00102c88,&DAT_00102c88,0x102ca2);
  return;
}



void FUN_00102102(void)

{
  ada__text_io__put__4(0x102cb4,&DAT_00102cb8,&DAT_00102cb8,0x102cb4);
  return;
}



void FUN_00102136(void)

{
  ada__text_io__put__4(&DAT_00102cc0,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cc0);
  return;
}



void FUN_0010216a(void)

{
  ada__text_io__put__4(&DAT_00102cc1,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cc1);
  return;
}



void FUN_0010219e(void)

{
  ada__text_io__put__4(&DAT_00102cc2,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cc2);
  return;
}



void FUN_001021d2(void)

{
  ada__text_io__put__4(&DAT_00102cc3,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cc3);
  return;
}



void FUN_00102206(void)

{
  ada__text_io__put__4(&DAT_00102cc4,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cc4);
  return;
}



void FUN_0010223a(void)

{
  ada__text_io__put__4(&DAT_00102cc5,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cc5);
  return;
}



void FUN_0010226e(void)

{
  ada__text_io__put__4(&DAT_00102cc6,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cc6);
  return;
}



void FUN_001022a2(void)

{
  ada__text_io__put__4(&DAT_00102cc7,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cc7);
  return;
}



void FUN_001022d6(void)

{
  ada__text_io__put__4(&DAT_00102cc8,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cc8);
  return;
}



void FUN_0010230a(void)

{
  ada__text_io__put__4(&DAT_00102cc9,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cc9);
  return;
}



void FUN_0010233e(void)

{
  ada__text_io__put__4(&DAT_00102cca,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cca);
  return;
}



void FUN_00102372(void)

{
  ada__text_io__put__4(&DAT_00102ccb,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ccb);
  return;
}



void FUN_001023a6(void)

{
  ada__text_io__put__4(&DAT_00102ccc,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ccc);
  return;
}



void FUN_001023da(void)

{
  ada__text_io__put__4(&DAT_00102ccd,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ccd);
  return;
}



void FUN_0010240e(void)

{
  ada__text_io__put__4(&DAT_00102cce,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cce);
  return;
}



void FUN_00102442(void)

{
  ada__text_io__put__4(&DAT_00102ccf,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ccf);
  return;
}



void FUN_00102476(void)

{
  ada__text_io__put__4(&DAT_00102cd0,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cd0);
  return;
}



void FUN_001024aa(void)

{
  ada__text_io__put__4(&DAT_00102cd1,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cd1);
  return;
}



void FUN_001024de(void)

{
  ada__text_io__put__4(&DAT_00102cd2,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cd2);
  return;
}



void FUN_00102512(void)

{
  ada__text_io__put__4(&DAT_00102cd3,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cd3);
  return;
}



void FUN_00102546(void)

{
  ada__text_io__put__4(&DAT_00102cd4,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cd4);
  return;
}



void FUN_0010257a(void)

{
  ada__text_io__put__4(&DAT_00102cd5,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cd5);
  return;
}



void FUN_001025ae(void)

{
  ada__text_io__put__4(&DAT_00102cd6,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cd6);
  return;
}



void FUN_001025e2(void)

{
  ada__text_io__put__4(&DAT_00102cd7,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cd7);
  return;
}



void FUN_00102616(void)

{
  ada__text_io__put__4(&DAT_00102cd8,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cd8);
  return;
}



void FUN_0010264a(void)

{
  ada__text_io__put__4(&DAT_00102cd9,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cd9);
  return;
}



void FUN_0010267e(void)

{
  ada__text_io__put__4(&DAT_00102cda,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cda);
  return;
}



void FUN_001026b2(void)

{
  ada__text_io__put__4(&DAT_00102cdb,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cdb);
  return;
}



void FUN_001026e6(void)

{
  ada__text_io__put__4(&DAT_00102cdc,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cdc);
  return;
}



void FUN_0010271a(void)

{
  ada__text_io__put__4(&DAT_00102cdd,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cdd);
  return;
}



void FUN_0010274e(void)

{
  ada__text_io__put__4(&DAT_00102cde,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cde);
  return;
}



void FUN_00102782(void)

{
  ada__text_io__put__4(&DAT_00102cdf,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102cdf);
  return;
}



void FUN_001027b6(void)

{
  ada__text_io__put__4(&DAT_00102ce0,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ce0);
  return;
}



void FUN_001027ea(void)

{
  ada__text_io__put__4(&DAT_00102ce1,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ce1);
  return;
}



void FUN_0010281e(void)

{
  ada__text_io__put__4(&DAT_00102ce2,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ce2);
  return;
}



void FUN_00102852(void)

{
  ada__text_io__put__4(&DAT_00102ce3,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ce3);
  return;
}



void FUN_00102886(void)

{
  ada__text_io__put__4(&DAT_00102ce4,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ce4);
  return;
}



void FUN_001028ba(void)

{
  ada__text_io__put__4(&DAT_00102ce5,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ce5);
  return;
}



void FUN_001028ee(void)

{
  ada__text_io__put__4(&DAT_00102ce6,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ce6);
  return;
}



void FUN_00102922(void)

{
  ada__text_io__put__4(&DAT_00102ce7,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ce7);
  return;
}



void FUN_00102956(void)

{
  ada__text_io__put__4(&DAT_00102ce8,&DAT_00102cb8,&DAT_00102cb8,&DAT_00102ce8);
  return;
}



void idk(void)

{
  ada__calendar__delays__delay_for(1000000000000000);
  FUN_00102616();
  FUN_001024aa();
  FUN_00102372();
  FUN_001025e2();
  FUN_00102852();
  FUN_00102886();
  FUN_001028ba();
  FUN_00102922();
  FUN_001023a6();
  FUN_00102136();
  FUN_00102206();
  FUN_0010230a();
  FUN_00102206();
  FUN_0010257a();
  FUN_001028ee();
  FUN_0010240e();
  FUN_001026e6();
  FUN_00102782();
  FUN_001028ee();
  FUN_001023da();
  FUN_0010230a();
  FUN_0010233e();
  FUN_0010226e();
  FUN_001022a2();
  FUN_001023da();
  FUN_001021d2();
  FUN_00102956();
  return;
}



void _fini(void)

{
  return;
}


