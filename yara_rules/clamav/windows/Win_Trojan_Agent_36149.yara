rule Win_Trojan_Agent_36149
{
strings:
	$a0 = { 8180e48180e48180e183abe48d9beca4b3eba5a6c88de38e80e48f85efaba2d7abeeafa8efbfbfe983bfe4ba90e490a9ee94a9ec9784ea9785ec94adec9785e9bb85e2b984ed95aaec9685eea8aee2a08eefb8b9ecb09ce6a0b0ebb0a2ebb083edbfb3eb97aae8ad8be2a78bebb084e7b4a0e3ad9decad8fe0acaaea94a5edbfb3eb97aaeb9eb0eaa2a9eaaeaaea87abeaa6a9ea8785ef818eec9785ec9785e895a8ec8ab1e4ba8de4b8b5e2bb85e4b8b3ec8683ec97a0e3ab85ea8cbaefb584e9be88eca6b0e8b58eec9bb9ea8c8defb184e88295ec9ab1e2ba8de4b0a0e7b586e89795e3a785eb8d8eef9b81e78485e6a486c7bdec9eb1e3b0aee4b28bc5b6e89795e4a385e0b5bee89795ef9b85e7908ce2b781ec95b0ec9785c986e29f81e4a0b3ea9986e89794e99785e49988ed9499ec9685e3aa95 }

condition:
	$a0
}

        