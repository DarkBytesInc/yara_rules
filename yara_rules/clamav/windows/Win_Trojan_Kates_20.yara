rule Win_Trojan_Kates_20
{
strings:
	$a0 = { c38d4000c38d4000c38d4000558bec33c055683110400064ff30648920ff050080400033c05a59596489106838104000c3e9ceffffffebf85dc38bc0832d0080400001c3558bec33c055686910400064ff30648920ff050480400033c05a59596489106870104000c3e996ffffffebf85dc38bc0832d0480400001c3ff253c9040008bc0ff25449040008bc0558bec33c05568b110400064ff30648920ff050880400033c05a595964891068b8104000c3e94effffffebf85dc38bc0832d0880400001c390aeef06ca953e56363a9546e25dceba23fd064ec51f75a6fa3bdefae50e02ce26f6dec620d8708ae4ca137aba1c1137224558457d22020a9a8fbab5e1749ab0789b6e83d04e9c154e361e06b05f49f123f39e326a40a97345c5a205a7a9b5523d8edf18f81d08464fe85fabdf292767417b5f916e8ffcb2cd49eb7557ab4bcc507da0e2af4918ed42799578f2d7612d }

condition:
	$a0
}

        