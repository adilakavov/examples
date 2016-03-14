<?php
namespace Api\Security\Authentication;

use Api\Exception\ApiException;
use Api\Security\SessionManager;
use Psr\Log\LoggerAwareTrait;
use Silex\Application;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class UserAuthenticator implements EventSubscriberInterface
{
    use LoggerAwareTrait;

    /**
     * @var Credentials
     */
    private $credentials;

    /**
     * @var SessionManager
     */
    private $sessionManager;

    /**
     * @var array
     */
    private $excludedRoutes = [];

    public function __construct(Credentials $credentials, SessionManager $sessionManager, array $excludedRoutes)
    {
        $this->credentials = $credentials;
        $this->sessionManager = $sessionManager;
        $this->excludedRoutes = $excludedRoutes;
    }

    /**
     * @param $route
     * @return bool
     */
    private function isExcludedRoute($route)
    {
        return in_array($route, $this->excludedRoutes);
    }

    /**
     * @param GetResponseEvent $event
     * @throws ApiException
     */
    public function onRequest(GetResponseEvent $event)
        /*Код данной функции не совсем мне понятен у на есть функция onRequest ей ты присваеваешь экземпляр класса
         GetResponseEvent, в теле переменной $request ты присваиваешь метод $event->getRequest() класса GetResponseEvent
        который возвращает public function getResponse()
    {
        return $this->response;
    } код взял из класса GetResponseEvent тут вопрос переменная  $request является объектом класса GetResponseEvent
        или в это переменной содержится значение response ?
         дальше переменной $route = $request->attributes->get('_route'); ты присваиваешь
       $route значение $request и тут же вызываешь метода другого класса, я понимаю что твой код правильный но не понимаю
        как ты можешь выызывать метод совершенно другого класса, наверное есть наследование ну где я мог бы его просмотреть
        а то это путает меня конкретно. потом вообще метод  get мне показывает что он вообще левый метод, я нашел всему этом
        объяснение что это все классы одного фреймворка и наверное тут идет какое то грамотное наследование, но не могу узнать как это проверить
           */
    {
        $request = $event->getRequest();
        $route = $request->attributes->get('_route');
        if ($this->isExcludedRoute($route)) {
            if ($this->logger) {
                $this->logger->info('Route excluded from auth');
            }
            return;
        }

        $authHeader = $request->headers->get('Authorization');
        if ($this->logger) {
            $this->logger->info('Authorization header', ['Authorization' => $authHeader]);
        }
        if (! preg_match('/^Token (.+)/i', $authHeader, $matches)) {
            $event->setResponse(new Response('', 401, ['WWW-Authenticate' => 'Token']));
            return;
        }
        $token = $matches[1];
        $userId = $this->sessionManager->getUserId($token);
        if (null === $userId) {
            throw ApiException::create(ApiException::INVALID_TOKEN);
        }
        $this->credentials->setUser($userId);
    }

    /**
     * Returns an array of event names this subscriber wants to listen to.
     *
     * The array keys are event names and the value can be:
     *
     *  * The method name to call (priority defaults to 0)
     *  * An array composed of the method name to call and the priority
     *  * An array of arrays composed of the method names to call and respective
     *    priorities, or 0 if unset
     *
     * For instance:
     *
     *  * array('eventName' => 'methodName')
     *  * array('eventName' => array('methodName', $priority))
     *  * array('eventName' => array(array('methodName1', $priority), array('methodName2'))
     *
     * @return array The event names to listen to
     */
    public static function getSubscribedEvents()
    {
        return [
            KernelEvents::REQUEST => 'onRequest',
        ];
    }
}
