<?php

/*
 * @copyright   2014 Mautic Contributors. All rights reserved
 * @author      Mautic
 *
 * @link        http://mautic.org
 *
 * @license     GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 */

namespace Mautic\ConfigBundle\EventListener;

use Mautic\ConfigBundle\ConfigEvents;
use Mautic\ConfigBundle\Event\ConfigEvent;
use Mautic\ConfigBundle\Service\ConfigChangeLogger;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

class ConfigSubscriber implements EventSubscriberInterface
{
    /**
     * @var ConfigChangeLogger
     */
    private $configChangeLogger;

    public function __construct(ConfigChangeLogger $configChangeLogger)
    {
        $this->configChangeLogger = $configChangeLogger;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            ConfigEvents::CONFIG_POST_SAVE => ['onConfigPostSave', 0],
        ];
    }

    public function onConfigPostSave(ConfigEvent $event): void
    {
        if ($originalNormData = $event->getOriginalNormData()) {
            // We have something to log
            $this->configChangeLogger
                ->setOriginalNormData($originalNormData)
                ->log($event->getNormData());
        }
    }
}
