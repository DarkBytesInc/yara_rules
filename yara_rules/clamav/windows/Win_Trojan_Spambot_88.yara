rule Win_Trojan_Spambot_88
{
strings:
	$a0 = { 0fbdd2368d15b9c148b4400d2ab49b9949930ae6fda389538f156a40ffff7ff51efd688e054deddede899f3ce3e5153564f1862a0b90755551b0ffffffffd14a5e2e7b8dd8e2126ffbffaf8e5eaedd202da54531269349c75a7847366997ffffffff8ac5f0ec83aa99f5551fe2cc }

condition:
	$a0
}

        
