rule Win_Trojan_Ciadoor_190
{
strings:
	$a0 = { 22629f5557e47aec44a869dc49609eacc2465f5353b738535a436655237b1e341fc9145d21f329bf79d8536ed68be873565e765df38cc6574ae87f185398f073af856df893cbc2642a248168d7f526fc4a5c7ad8eb4b322db77476cccda0124db371e6d8ac3aa24042870cb11f007622e2e8aa4c4b6313cd47702e507f7b0265faa93a7d1aa1af56617bce1d }

condition:
	$a0
}

        