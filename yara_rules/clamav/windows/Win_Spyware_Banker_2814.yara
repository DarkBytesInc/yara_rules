rule Win_Spyware_Banker_2814
{
strings:
	$a0 = { 1da5fe8b97c3e450efceb50c4bde97ddd3f668412a60d79bf8f807dce5ee50776853e5bd346b3cc7235b5c86e58ca688eeccb64f8fd3e05e6feb986061463895e7917301a2ca12962fe6f970ddba597afa58e025b4d00c52ab6d8e24afcd201134d0f4ec7c198c8e6ce1d368c5a6 }

condition:
	$a0
}

        
