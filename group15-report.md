# Group 15 Secure Coding Report

## Group Members

| Group Member | Student Number |
|:------------:|:--------------:|
| Ryan Allagapen | 23476285 |
| Dante McGee | 23813728 |
| Seoyoung Park | 23902644 |
| Stewart van Hoek | 23720987 |
| Jeet Vora | 23970542 |

---

## Discussion of Design Considerations

>### Approach for Separation of Responsibilities

---

We set up issues on GitHub and utilised a Kanban board to track tasks. This allowed us to be flexible when taking on tasks as when we had time, we could see what needed to be done and assign the task to ourselves. We completed coding throughout one week and then got together to have a code review of each function, with each person presenting what they had done.

---

>### Prevention of Integer and Buffer Overflows

---



---

>### Validation and Sanitisation

---



---

>### Hashing and Salting Algorithms

---

To implement our `account_validate_password()` and `account_update_password()` functions, (the latter of which was used to also set the initial password in `account_create()`), we utilised `scrypt`, as it was simple to implement and is a well-tested and well-used password hashing algorithm. From the list of password hashing algorithms from `Lecture 8` (`Argon2id`, `scrypt`, `bcrypt`), we decided to pick the simplest to implement while also being well-tested and proven (to date) to be secure. As such, we did not go with `Argon2id` as `scrypt` appeared simpler to implement. We also chose not to go with `bcrypt` as it is only CPU bound - meaning that attackers can compute many hashes derived from `bcrypt` in parallel for a far lower memory cost than `scrypt`, which is `memory-hard`. As such, `scrypt` is more resistant to large scale brute-force attacks than `bcrypt`.

---

## Discussion of Testing

>### Use of ___

---



---

>### Use of ___

---



---

>### Use of ___

