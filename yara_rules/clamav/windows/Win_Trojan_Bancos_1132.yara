rule Win_Trojan_Bancos_1132
{
strings:
	$a0 = { 2f44791a20efbec0845c1a057a0fcb20ec4dd986b4f1411c222dbc5c418a09fde39a063969af704fe33278acab793f71aad0035a4f44b8c22a297fd123f97d92ee74df2af5d4de17a7d02c5ec4947f4991aa6cd713f7fbce7cda2cf7a05a1dabb98c }

condition:
	$a0
}

        
