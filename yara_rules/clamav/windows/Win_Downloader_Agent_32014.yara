rule Win_Downloader_Agent_32014
{
strings:
	$a0 = { d70efd53d75efd53235e8f03b31f3016d47b8cfe962470167b66080d6b0e8f6333f165ae3a4e7095ef1efd53d75e8f03bf1f3016a04b68dfe88334323b646046410d8f620f168f620f168f620f1698db080e7095ef16b343a0e2f3fa3f8d15fa2b582725eb830de6411edbbd8050fd53d75efd53c75ef963d7f10506d47b7ce95e069837080e7095ef1af4d65f2f4963d77b6ce95e1a }

condition:
	$a0
}

        