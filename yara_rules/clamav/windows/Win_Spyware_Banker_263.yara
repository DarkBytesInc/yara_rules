rule Win_Spyware_Banker_263
{
strings:
	$a0 = { 386f2fc960a46ea4282b2d31186f62107e515813d77a4c5fa74929894bdda0198765c52b8f0a0a869fb02a6d4b4f8cf71434ec8866d27024f9b67b96df7ed08b21f056f104eab9915299fb5dc0927fb256e6622cc8686f88e87253d9e164b72bf7433453aa6af3a77e7ae3eaaa5c24b96d774237e20c466e6d5e3c76942ebf3ef316866496dc7c38f210430043e1eb5c52b70b90 }

condition:
	$a0
}

        