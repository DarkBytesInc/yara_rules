rule Win_Trojan_Pyros_3
{
strings:
	$a0 = { d200bf0001a5a5a5e80600071f680001c3b44e8d96c300b90700cd21e866007309e87f00b44fcd21ebf2b44e8d96c900b90700cd21e84d007309e86600b44fcd21ebf2c35b5079726f735d005b5275696e6572202f4349485d002a2e434f4d002a2e45584500050002 }

condition:
	$a0
}

        