rule Win_Downloader_91908_1
{
strings:
	$a0 = { f0c187fe632ff943cd4d012862a07bf1fff484e7111eb421fda0ffff6742f460ec1ff9ff0b2ef99b265900330000000000004e7773000047725833000000583400004a61005900006b00545300396174004d450061000061544134007a000036364d54427278414633007500004e006b00380000554c6f6e0000000000005300005447005000000074000000777263000000364c005100546600007434000000 }

condition:
	$a0
}

        