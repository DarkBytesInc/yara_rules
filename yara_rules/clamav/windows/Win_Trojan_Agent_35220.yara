rule Win_Trojan_Agent_35220
{
strings:
	$a0 = { d643372564ed5dcd19ae57066a43866006aeae7a488afa2fcf092400641afb9fb08cd1cab25569197ceab4b88c392ac6f7caf070e91e4dd5dae0407629d47a8ed87381d56a8d98ab354f7cbd9f9acc3a7cf2acb6d725ea8d7971 }

condition:
	$a0
}

        
