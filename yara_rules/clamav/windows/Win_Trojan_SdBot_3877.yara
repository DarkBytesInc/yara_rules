rule Win_Trojan_SdBot_3877
{
strings:
	$a0 = { b23a1f24fa7ba4e19c0ceba250f17bc350da5facd478ba36a30387844716d5193938f8ff74dc4da2101609ca64382f2341cdd42c423e9f8f14de37b24d53e51ed7ad7502f85daedc91f979bc9763af905d2305aaf2d26b6386f756ac }

condition:
	$a0
}

        
