rule Win_Trojan_SdBot_2097
{
strings:
	$a0 = { d0ea9d53aa7b5d56697b5e3d5ff6374f4e636e9e37a9e3a7a72a9bd194f5bd8de97e0cfc91fbffbfd53ae7dcd1f68e782f7ee77eef3b8c824c3dfd3dbfc92ffd7597f50008fed1dbfec08bfc5fe6ee4daf2eadae7e1423f6c7373ff7d536d7b59766c7c736d5469756cfe626ffb55876696c58706a79697980fec3fea56de5d9 }

condition:
	$a0
}

        
