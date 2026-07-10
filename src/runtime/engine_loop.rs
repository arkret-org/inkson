use std::time::Duration;

use garth::Backoff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineLoopDirective {
    ContinueAfter(Duration),
    Retry { minimum_delay: Option<Duration> },
    Pause(Duration),
    Stop,
}

pub async fn run_engine_loop<Active, Step>(
    floor: Duration,
    ceiling: Duration,
    mut active: Active,
    mut step: Step,
) where
    Active: FnMut() -> bool,
    Step: AsyncFnMut() -> EngineLoopDirective,
{
    let mut backoff = Backoff::new(floor, ceiling);
    while active() {
        match step().await {
            EngineLoopDirective::ContinueAfter(delay) => {
                backoff.reset();
                crate::runtime_helpers::sleep_for(delay).await;
            }
            EngineLoopDirective::Retry { minimum_delay } => {
                crate::runtime_helpers::sleep_for(backoff.next_delay_with_hint(minimum_delay))
                    .await;
            }
            EngineLoopDirective::Pause(delay) => {
                backoff.reset();
                crate::runtime_helpers::sleep_for(delay).await;
            }
            EngineLoopDirective::Stop => return,
        }
    }
}
