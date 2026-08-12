---
title: KRYPTON DEMO
---

# KRYPTON 
---

## 1. Create tenant
## 2. Announce keys
## 3. Activate keys
## 4. Mongodb KMIP 

<!-- end_slide -->

# DEMO Setup
---

```text
                          ┌─────────────────────────────────┐
                          │       KRYPTON ROOT              │
  ┌──────┐      R         │                                 │
  │ User │──────O────────▶│    ┌─────────────┐              │
  └──────┘                │    │   K0 ROOT   │              │
                          │    └─────────────┘              │
                          │                                 │
  ╭──────────╮◀──────────▶│    ┌─────────────┐◀───▶╭──────────────╮
  │ POSTGRES │            │    │   K1 KEK    │     │   K1-vault   │
  ╰──────────╯◀──────────▶│    └─────────────┘◀───▶╰──────────────╯
                          │                                 │
                          │    ┌─────────────┐◀───▶╭──────────────╮
                          │    │   K2 DEK    │     │   K2-vault   │
                          │    └─────────────┘◀───▶╰──────────────╯
                          │                                 │
  ┌──────────┐   R        │    ┌─────────────┐              │
  │ MONGODB  │───O────────────▶│ KMIP SERVER │              │
  └──────────┘            │    └─────────────┘              │
                          │                                 │
                          └─────────────────────────────────┘
```

<!-- end_slide -->
# KRYPTON KEY Lifecycle

```
    ┌──────────────────────────────────────────────────────┐
    │                  TRANSITION TABLE                    │
    ├─────────────────┬────────────────────────────────────┤
    │ From            │ To                                 │
    ├─────────────────┼────────────────────────────────────┤
    │ PreActivation   │ Active, Destroyed, Compromised     │
    │ Active          │ Suspended, Deactivated,            │
    │                 │ Destroyed, Compromised             │
    │ Suspended       │ Active, Deactivated,               │
    │                 │ Destroyed, Compromised             │
    │ Deactivated     │ Destroyed, Compromised             │
    │ Compromised     │ Destroyed                          │
    │ Destroyed       │ [terminal]                         │
    └─────────────────┴────────────────────────────────────┘
```
`

<!-- end_slide -->
#  Key Management Execution (KRYPTON)
## 1. Create tenant

<!-- end_slide -->

#  Key Management Execution (KRYPTON)
## 1. Create tenant
## 2. K0 Announce key 

<!-- end_slide -->

#  Key Management Execution (KRYPTON)
## 1. Create tenant
## 2. K0 Announce key 
## 3. K0 Activate key

<!-- end_slide -->

#  Key Management Execution (KRYPTON)
## 1. Create tenant
## 2. K0 Announce key 
## 3. K0 Activate key
## 4. K1 Announce key 

<!-- end_slide -->

#  Key Management Execution (KRYPTON)
## 1. Create tenant
## 2. K0 Announce key 
## 3. K0 Activate key
## 4. K1 Announce key 
## 5. K1 Activate key

<!-- end_slide -->

#  Key Management Execution (KRYPTON)
## 1. Create tenant
## 2. K0 Announce key 
## 3. K0 Activate key
## 4. K1 Announce key 
## 5. K1 Activate key
## 6. K2 Announce key 

<!-- end_slide -->
#  Key Management Execution (KRYPTON)
## 1. Create tenant
## 2. K0 Announce key 
## 3. K0 Activate key
## 4. K1 Announce key 
## 5. K1 Activate key
## 6. K2 Announce key 
## 7. K2 Activate key

<!-- end_slide -->

# KMIP Client configuration (MongoDB)
## 1. Create the certification with the client ID

<!-- end_slide -->

# KMIP Client configuration (MongoDB)
## 1. Create the certification with the client ID
## 2. Add the keyIdentifier 
<!-- end_slide -->

# KMIP Client configuration (MongoDB)
## 1. Create the certification with the client ID
## 2. Add the keyIdentifier 
## 3. Check the logs

<!-- end_slide -->

# KMIP Client configuration (MongoDB)
## 1. Create the certification with the client ID
## 2. Add the keyIdentifier 
## 3. Check the logs
## 4. Check the raw blob 

<!-- end_slide -->
# THANK YOU

<!-- end_slide -->




