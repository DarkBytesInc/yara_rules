rule Win_Trojan_VB_385
{
strings:
	$a0 = { 42797a7379006284402058481c4e4838176a9b2d400640622ae0028479167e4de0a0524d885a19400138de5535d7e001451f0e5d3995f4842b07f2156cca301b21cf06022f29668fa49a0d58ada1487d423d573cc69128ba9815fc001e24314b347e08333ad8036966c7437a1075b23b614cbaac274334bbdfadec9b27dc2483c33453571a7bac10250b08c1256588866527d3 }

condition:
	$a0
}

        