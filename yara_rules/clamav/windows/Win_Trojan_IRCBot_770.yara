rule Win_Trojan_IRCBot_770
{
strings:
	$a0 = { 227ffa0edc56fd88a8c1842165fbfe72015f385792998cce8e08bb1978cbc0eee3f4ecd3f10820ca68bb9549ec7ee96bdbcbf3d3f81ac50881228d5744015b9619e29f11c5715f13f75051eabb437d4e395f52b0188720e799d91bbabdcd5ef5b1e0a9504ed8c6484e0761f4b4c9eb698332680d07a395efba3b7f9d06bf0d9b5a8c387d079de32e01098418a41f3a27b2 }

condition:
	$a0
}

        