rule Win_Trojan_SdBot_125
{
strings:
	$a0 = { 217f3f522da4030ce9dd4bb3726526327b1c6d10e022065769466df5052c7532373f1364506fe20b5b714c1c8339f7e175534c0d08b46d1341056451fc281d66e7a73c980ac40180806570ebb4294b5469098a06de230c84c00accb0f720e109bd2b48d24dd336f33188c04fa80af1c0197f84ffaa0477fc57aff94215e8252564100658464601e58b165f44f397940e12c84db092ee }

condition:
	$a0
}

        