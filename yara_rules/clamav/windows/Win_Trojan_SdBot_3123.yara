rule Win_Trojan_SdBot_3123
{
strings:
	$a0 = { 1784270d253249cc7d4580562138d4f050d3862348d41fcce266600b8c0945b03bf280e83842d4e83846d4a433402f320f1c0914240c480495fc8432f409ec29df9580d838d48484f16450095c4870a77e80d562d0d5167b808d62d8d418d0d589e89919081330f67d4d80c2d0d51d42d0d535485c66840f648c0994489c91a422ac44b4c78a77e58076ac2066e00de80944f80c4fd6 }

condition:
	$a0
}

        