package com.example

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.application.*
import io.ktor.response.*
import io.ktor.request.*
import io.ktor.features.*
import io.ktor.routing.*
import io.ktor.http.*
import io.ktor.auth.*
import com.fasterxml.jackson.databind.*
import io.ktor.auth.jwt.jwt
import io.ktor.jackson.*
import java.util.*
import java.util.concurrent.CopyOnWriteArraySet
import java.util.concurrent.atomic.AtomicInteger

fun main(args: Array<String>): Unit = io.ktor.server.netty.DevelopmentEngine.main(args)

@Suppress("unused") // Referenced in application.conf
fun Application.module() {
    install(CORS) {
        method(HttpMethod.Options)
        method(HttpMethod.Put)
        method(HttpMethod.Delete)
        method(HttpMethod.Patch)
        header(HttpHeaders.Authorization)
        allowCredentials = true
        anyHost() // @TODO: Don't do this in production if possible. Try to limit it.
    }

    install(StatusPages) {
        exception<InvalidCredentialsException> { exception ->
            call.respond(HttpStatusCode.Unauthorized, mapOf("OK" to false, "error" to (exception.message ?: "")))
        }
    }

    val simpleJWT = SimpleJWT("mysecretgood")
    install(Authentication) {
        //        basic {
//            realm = "myrealm"
//            validate { if (it.name == "user" && it.password == "password") UserIdPrincipal("user") else null }
//        }

        jwt {
            verifier(simpleJWT.verifier)
            validate {
                UserIdPrincipal(it.payload.getClaim("name").asString())
            }
        }
    }

    install(ContentNegotiation) {
        jackson {
            enable(SerializationFeature.INDENT_OUTPUT)
        }
    }

    routing {
        route("/snippets") {
            get {
                call.respond(SnippetRepo.get())
            }

            authenticate {
                post {
                    val post = call.receive<PostSnippet>()
                    val principal = call.principal<UserIdPrincipal>() ?: error("No principal")
                    val snippet = SnippetRepo.add(Snippet(principal.name, post.snippet.text))
                    call.respond(mapOf("snippet" to snippet))
                }

                delete("{id}") {
                    val id = call.parameters["id"] ?: throw IllegalArgumentException("Parameter id not found")
                    call.respond(SnippetRepo.remove(id.toInt()))
                }
            }
        }

        post("/login-register") {
            val post = call.receive<LoginRegister>()
            val user = users.getOrPut(post.user) { User(post.user, post.password) }
            if (user.password != post.password) throw InvalidCredentialsException("Invalid Credentials")
            call.respond(mapOf("token" to simpleJWT.sign(user.name)))
        }
    }
}

class InvalidCredentialsException(message: String) : RuntimeException(message)

open class SimpleJWT(val secret: String) {
    private val algorithm = Algorithm.HMAC256(secret)
    val verifier = JWT.require(algorithm).build()
    fun sign(name: String): String = JWT.create().withClaim("name", name).sign(algorithm)
}

class User(val name: String, val password: String)
class LoginRegister(val user: String, val password: String)

val users = Collections.synchronizedMap(
        listOf(User("test", "test"))
                .associateBy { it.name }
                .toMutableMap())

data class Snippet(val user: String, val text: String) {
    var id: Int? = null
}

data class PostSnippet(val snippet: PostSnippet.Text) {
    data class Text(val text: String)
}

object SnippetRepo {
    private val idCounter = AtomicInteger()
    private val snippets = CopyOnWriteArraySet<Snippet>()

    fun get() : List<Snippet>  = snippets.toList()

    fun get(id: Int) : Snippet {
        return snippets.find { it.id == id } ?: throw IllegalArgumentException("Mo entity found for $id")
    }

    fun add(s: Snippet): Snippet {
        s.id = idCounter.incrementAndGet()
        snippets += s
        return s
    }

    fun remove(id: Int) {
        val snippet = get(id)
        snippets.remove(snippet)
    }
}
