<?php
namespace Api\Security\Authentication;

use PHPUnit_Framework_TestCase;
use Symfony\Component\HttpFoundation\HeaderBag;
use Symfony\Component\HttpFoundation\Request;

class UserAuthenticatorTest extends PHPUnit_Framework_TestCase
{
    private $credentials;
    private $sessionManager;
    /**
     * @var UserAuthenticator
     */
    private $authenticator;

    public function setUp()
    {
        $this->credentials = $this->getMock('\\Api\\Security\\Authentication\\Credentials');
        $this->sessionManager = $this->getMockBuilder('\\Api\\Security\\SessionManager')
            ->disableOriginalConstructor()
            ->getMock();

        $this->authenticator = new UserAuthenticator($this->credentials, $this->sessionManager, ['excluded']);
        /*откуда взялся этот код и к какой части кода он относится, меня с пантологии сбивает именно тот факт
        что в тестируемом классе нет переменной которая называлась бы authenticator которая бы объявлялась объектом
        UserAuthenticator, я понимаю что этот код соответствует конструктору класса UserAuthenticator но где в конструкторе
        authenticator я не видел. */
    }

    /**
     * @expectedException \Api\Exception\ApiException
     * @expectedExceptionMessage Invalid or expired auth token
     * @expectedExceptionCode 202
     */
    public function testOnRequestThrowsException()
    {
        $request = new Request([], [], ['_route' => 'secured-route']);
        /* тут $request ты делаешь объетом класс Request у которого в конструкторе содержится такой код

Request::__construct(array $query = array(), array $request = array(), array $attributes = array(),
        array $cookies = array(), array $files = array(), array $server = array(), $content = null)
        получается что в параметрах в пустых скобках ты пропускаешь массив array $query = array(), array $request = array()
        и массиву array $attributes = array() ты устанавливаешь ['_route' => 'secured-route'] правильно ли я понял что
        коду этого теста соответствует вод этот код  с оригинального класса
        $route = $request->attributes->get('_route'); если да то у меня два вопроса. 1 вопрос почему не написанно в тесте
        $route = $request = new Request([], [], ['_route' => 'secured-route']);  и 2 вопрос отал потому как свойство attributes
        принадлежит классу request. ответь тогда на первый вопрос.  */
        $request->headers = new HeaderBag(['Authorization' => 'Token zzz']);
        /*как я понял этому тесту соответствует этот код $authHeader = $request->headers->get('Authorization');
        теперь вопрос, метод headers является методом класса Request ты делаешь это  свойство классом объекта HeaderBag
        хотя в оригинальном коде нет на это и упоминания просто перечисление цепочки методов, я не совсем понял как оно так.*/

        $event = $this->getMockBuilder('Symfony\\Component\\HttpKernel\\Event\GetResponseEvent')
            ->disableOriginalConstructor()
            ->setMethods(['getRequest'])
            ->getMock();
        $event->method('getRequest')->willReturn($request);

        $this->authenticator->onRequest($event);

    }
}
