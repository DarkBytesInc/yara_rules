rule Win_Trojan_SdBot_4443
{
strings:
	$a0 = { 1f7dd238a02aa4dc2ba07d419c37eba7277592a1474672f3e78dce400a3ba8af46fdb677abad542ae963aae0d0198d659c6f4611d848c891015357502571795e564ae3b05ebd0ba551ad2c15c5e5cc113d8b6a21e8ec51dcf8e03a305a6a9c7cedd1df11ee7e004e602afffdd47fcef3d796808f992d54c7c82fd9c409bab324 }

condition:
	$a0
}

        