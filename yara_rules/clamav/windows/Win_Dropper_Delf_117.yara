rule Win_Dropper_Delf_117
{
strings:
	$a0 = { 605336d27072e06124f8e574e0d4533a1df5fd21773aa96d9721e8f857de8a83d4f23b7feaf27e9490cd8225557be53c5446ea2b4d53c54ab9e85cf3a8a7bf66ca699a4f5fe0386b54356768682a2b50bf5bc64313c4c863e469eff5bcf9a9f1b85ccdfdf8cb6617fd7401163e8c15dd832cd5e9fe6ce65449e6f15f41adc351faf20c69fe78d1dc145b69ea89 }

condition:
	$a0
}

        