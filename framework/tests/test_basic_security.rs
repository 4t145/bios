/*
 * Copyright 2022. gudaoxuri
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use bios::basic::result::BIOSResult;
use bios::BIOSFuns;

#[tokio::test]
async fn test_basic_security() -> BIOSResult<()> {
    let b64_str = BIOSFuns::security.base64.encode("测试");
    let str = BIOSFuns::security.base64.decode(&b64_str).unwrap();
    assert_eq!(str, "测试");
    Ok(())
}
