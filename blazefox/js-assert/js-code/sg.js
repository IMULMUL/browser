let A = {
	foo : 0x1337,
	blazh : "wjllz"
};

print("[+] 1: " + addr(A)) ;
let B = {
	foo : 0x1338,
	blazh : "sup"
};

print("[+] 2: " + addr(B)) ;

let C = {
	foo : 0x1338,
	blazh : "sup",
};

C.another = 0x41414141;

print("[+] 3: " + addr(C)) ;
readline();
