rule Win_Trojan_SdBot_3457
{
strings:
	$a0 = { 2b270c58e61a9f2382b962763d905c4147473aa61a5a0a2ca3a83634eff729d8f49cf172bf8a8a2b0f743b388f05e9c5a5d1131db95240c4cd288bf065949ad0328673b1ee8c482da010a92c82e782a194991b03edf4e4d57da70f575488ed22bd02f6f2c7b6eb7f013b73875104459446f5c71bff128c489c39fef5f42ab68adc30904f5a0f900d7e854ada1381 }

condition:
	$a0
}

        