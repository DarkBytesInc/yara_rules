rule Win_Trojan_Agent_31647
{
strings:
	$a0 = { aacefcf4e6d9d15456dc981f1105f5d918ae7f5c85f562999a48beb3564bcc0f596055d18540485733e50561eda8d7c3424bd7da27394ef3db3bc6fd5d374409e82dcd856bb2f088380db246dd03c3352a65b57d58a1aea45c4aac487751df2a10f08b94a67c7b1de97ccda8746957f8615cc77e6ac747cc165bd5b5de5c9223cb6e93205c7ac7ec561c24dc8a4817eddebd34680f }

condition:
	$a0
}

        