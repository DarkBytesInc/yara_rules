rule Win_Downloader_Zlob_1536
{
strings:
	$a0 = { 786fc1c8d9e85f7b23f76cf8b06ff0bba6d0d559d54f2e0df4abd7c9d24ce9b44a61899f264500a056904e9b3c6a632ca1265e25bcfa4243eb2cbf4397e61cbf2186aae6b328e471eadfd8e36dbcf90aa1fd05e0fa1c658741198fc6ad5bed57f625df15d878a2 }

condition:
	$a0
}

        
