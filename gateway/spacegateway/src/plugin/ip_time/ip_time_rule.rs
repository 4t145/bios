use std::{ops::Range, default, time::SystemTime};

use serde::{Deserialize, Serialize};
use tardis::chrono::{NaiveTime, Utc, Local};

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default)]
pub enum IpTimeRuleMode {
    WhiteList,
    #[default]
    BlackList,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct IpTimeRule {
    pub time_allow: Vec<Range<NaiveTime>>,
    pub time_ban: Vec<Range<NaiveTime>>,
    pub mode: IpTimeRuleMode
}

impl IpTimeRule {
    pub fn check_by_time(&self, time: NaiveTime) -> bool {
        let contains_time = |range: &Range<NaiveTime>| range.contains(&time);
        match self.mode {
            IpTimeRuleMode::WhiteList => {
                self.time_allow.iter().any(contains_time)
            },
            IpTimeRuleMode::BlackList => {
                !self.time_ban.iter().any(contains_time)
            },
        }
    }
    pub fn check_by_now(&self) -> bool {
        self.check_by_time(Local::now().time())
    }
}