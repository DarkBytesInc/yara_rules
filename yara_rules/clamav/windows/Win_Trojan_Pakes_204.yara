rule Win_Trojan_Pakes_204
{
strings:
	$a0 = { 08cd909ff704a11372f3f9801805b27f005222676963d054dd50ce8cc2000a6d5d7c4c70bb9700db40031862ff9682131ac5110cf49da01074330180d826c2a0ddb0d0363e2e715c0100f1ef8cf96c771e427b8b7018f4e4350393966a45ca3a91f3602400e600377f89093975f46900eb1bb8db76c0c65000cc85b98ceff845940018c583622b78e9e00054 }

condition:
	$a0
}

        