rule Win_Trojan_QQRob_44
{
strings:
	$a0 = { 1504c0c223df01397f9ee79ee3f07591a4e040fef146ebe708a45c2260926b954622c98800615ce50c5d69974ef9b9b995f510d1802cb857beee087da741c197181ff6c819882dee489502aea75760cabfeaff5e44333d8e695adeacd1a9c26ff419f275d30d829341a6125247cc }

condition:
	$a0
}

        