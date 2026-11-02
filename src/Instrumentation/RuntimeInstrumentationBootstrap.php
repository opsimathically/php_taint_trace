<?php

declare(strict_types=1);

namespace PhpTaintTrace\Instrumentation;

use Throwable;

final class RuntimeInstrumentationBootstrap
{
    public function __construct(
        private readonly InstrumentationBackendInterface $backend
    ) {
    }

    public function bootstrap(BaselineHookPlan $plan, HookHandlerRegistry $handlers): InstrumentationBootstrapReport
    {
        $report = new InstrumentationBootstrapReport($this->backend->backendName());
        $capabilities = $this->backend->capabilities();

        foreach ($plan->hooks() as $hook) {
            if (!$capabilities->supports($hook->kind())) {
                $report->skip(
                    $hook,
                    sprintf(
                        'Backend does not support %s hooks.',
                        $hook->kind()->value
                    )
                );
                continue;
            }

            try {
                $this->backend->registerHook($hook, $handlers->resolve($hook));
                $report->register($hook);
            } catch (Throwable $error) {
                $report->skip($hook, $error->getMessage());
            }
        }

        return $report;
    }
}
