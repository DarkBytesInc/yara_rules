rule Win_Spyware_Zbot_1269
{
strings:
	$a0 = { 558bec83ec448165e8000000008d13f76c240421f7ff358d3640008d7d00ff35963d400081c6ab1a40002b05b55940005139f97507877d008b54241421f78d405c83ebe00305741c400009feff15a03a40008d5d08ff05865d40002b7424080115415f4000ff15a8104000034d00c705955c4000644e4000c38d542484f76c24 }

condition:
	$a0
}

        