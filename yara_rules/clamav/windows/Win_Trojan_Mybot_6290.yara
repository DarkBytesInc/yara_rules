rule Win_Trojan_Mybot_6290
{
strings:
	$a0 = { c6589aca70316f6969700dcc16aa3e091d1422b0cbf5b1fcb9b9382a8264d02a970ab76e762ce3b3f2e1154fe8d382c38e81df790ed1199b8276afecdddd3cd419ddcdba84625dbd379a3a0537b804851bed7da5acf88238aa989b4d58d734a07a305a9b0c4c6b94514a8cd924580fb605a599b9f16aa415a9be26cc563363e6dd575c3265e0d3df51aa2d91be15297a9ed2181a2c1a }

condition:
	$a0
}

        