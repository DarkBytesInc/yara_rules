rule Win_Trojan_Elohim_1
{
strings:
	$a0 = { 36716c0100126a265b456e747269657320666f72204d49484f4c4548204841524142205449485348455245425d3a6436716c0100126a0131644c716c0100646467de0073870212737f000c69087072656d66656e24127386000c69056e6f6d6324127301000c6a084175746f4f70656e12738f030c6c030064 }

condition:
	$a0
}

        