rule Win_Trojan_Agent_33354
{
strings:
	$a0 = { 4f58ed1d5e160c77007867017d00cfb502cc19d67a24a1af0524e7fb28de5f5b6ac93aa2cfdeade09ba7eafa12d74b8e8f05cb6bebf7e192d124ecfbe759c5b7bef76f98ea7211a473457f8a288da80b6eccd819b062ed50375c08c6d9cd }

condition:
	$a0
}

        
