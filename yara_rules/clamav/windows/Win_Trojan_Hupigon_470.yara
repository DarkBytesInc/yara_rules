rule Win_Trojan_Hupigon_470
{
strings:
	$a0 = { 445ffeffb228d8459cf87ab805f7b1e340a4c510b41cfeddbed0a92cbddbf43f9c25543491b285fad268786e2bcfa8c02b5d840aa88554a78cdfd0e150f38b8626dfa9669e35972cfe3ca97d67abddf31fb4c3f175dc22e960714fd54bb02efeec8d9139b887a5a7680ddfe87052ec8f8e303982d76dbd422c20a4bd9f603d01e11f2541a39dd0e77e15ea838c026bfe8d }

condition:
	$a0
}

        