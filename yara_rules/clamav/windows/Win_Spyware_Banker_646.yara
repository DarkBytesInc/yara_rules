rule Win_Spyware_Banker_646
{
strings:
	$a0 = { 4e63f788ea434265126f6c3089e1fe56fb02af90c7198a7256d1eea0ec084d5281160d2698f4209d69c8b8e0f68ebfaeec6307b0f6b659218a1152ec86159efded97feed956dd2bcc4b2158094c52cadddbdc6ea862ca8d58dbaaee69831b62a9c78606c4600fa9e87dadbda31d03318014cf2e56d04836722ad3de33780635b148d9fc374fea2bf1afe18676b46504d134984401b6c }

condition:
	$a0
}

        