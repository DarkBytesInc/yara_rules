rule Win_Spyware_Banker_2183
{
strings:
	$a0 = { 954fdaf6ed7b193b3f68a3cea48f50535a5ba1f513a2eceeda8dd3c75b80514d08410416186af48a2ad6eebfb0d9d5d3101fe9945411804748e4185fa6cbd71ac3addd26d1e1b1422d7323a27634099ee2e1a664a0a4341e228199bb207ca97f02a5c0bc47955598c942824589f893d45eec7490aadfafc225da4082aa677fd0ea9e2c4adf8a2a769738212c9259 }

condition:
	$a0
}

        