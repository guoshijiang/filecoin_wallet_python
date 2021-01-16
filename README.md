# filecoin_wallet_python
### 生成地址测试案例

###### 生成地址只支持 secp256k1 版本的
```
from secp256k1 import PrivateKey
privkey = PrivateKey()
# pubkey_ser = privkey.pubkey.serialize()
pubkey_ser_uncompressed = privkey.pubkey.serialize(compressed=False)
print(privkey.serialize())
print(pubkey_ser_uncompressed.hex())
print(pubkey_to_address(pubkey_ser_uncompressed.hex()))
```


###### 离线签名版本
```
from common.transaction import FilTransaction
fs = FilTransaction(
    "f1u4guc6t5ungjvjkjh3y2aqru6of3ap75vcny6yy",
    "f1nfuxedw57h3cl5e7wjngab577j6gyeqxk5lsrna",
    0,
    10000000000000000,
    9028272,
    10988008062,
    2001083,
    0,
    "",
    0
)
pub_key_s = '04a75ca299fa5f4b7afdafb88ff5300ca88efe02de01e364a7ede4563c1054feb5ae5c764949c94a005aab8331343591c994fd003dff05cd0e7d488da0ca7a764f'
pri_key = 'bc98b2581a15c8773c98e69f5f410fe33c65ad0b28c5916b1455abe3dea59456'
print(filecoin_sign(fs, pri_key, pub_key_s))
```
