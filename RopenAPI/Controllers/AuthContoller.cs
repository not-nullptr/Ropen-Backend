using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.Reflection;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using MongoDB.Driver;
using MongoDB.Bson;
using System.Security.Cryptography;
using Crypt;
using System.Text;
using MongoDB.Bson.Serialization;
using System.Text.RegularExpressions;

namespace RopenAPI.Controllers
{


    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpPost("v2/signup")]

        public IActionResult signUp(UserInfo info)
        {

            var resp = new HttpResponseMessage();
            var dbClient = new MongoClient("mongodb://127.0.0.1:27017");
            IMongoDatabase db = dbClient.GetDatabase("roblox");
            var users = db.GetCollection<BsonDocument>("users");
            var returnobject = JObject.Parse("{}");
            returnobject["starterPlaceId"] = "-1";
            string RandomDigits;
            var random = new Random();
            string s = string.Empty;
            for (int i = 0; i < 9; i++)
                s = String.Concat(s, random.Next(10).ToString());
            RandomDigits = s;
            returnobject["userId"] = RandomDigits;
            var password = Crypt.Crypt.HashPassword(info.password);
            string token = Crypt.Crypt.GenerateUniqueHexString(777);
            var data = new BsonDocument
            {
                { "starterPlaceId", returnobject["starterPlaceId"].ToString() },
                { "userId", returnobject["userId"].ToString() },
                { "username", info.username },
                { "password", password },
                { "gender", info.gender },
                { "birthday", info.birthday },
                { "displayName", info.username },
                { "token", token }
            };
            users.InsertOneAsync(data);
            Response.Headers.Append("access-control-allow-methods", "GET, PUT, POST, DELETE, HEAD");
            Response.Headers.Append("report-to", "{\"group\":\"network-errors\",\"max_age\":604800,\"endpoints\":[{\"url\":\"https://ncs.roblox.com/upload}]}");
            Response.Headers.Append("nel", "{\"report_to\":\"network-errors\",\"max_age\":604800,\"success_fraction\":0.001,\"failure_fraction\":1}");
            Response.Headers.Append("roblox-machine-id", "CHI1-WEB3816");
            Response.Headers.Append("p3p", "CP=\"CAO DSP COR CURa ADMa DEVa OUR IND PHY ONL UNI COM NAV INT DEM PRE\"");
            Response.Headers.Append("cache-control", "max-age=120, private");
            Response.Headers.Append("access-control-allow-origin", "https://www.roblox.com");
            Response.Headers.Append("access-control-allow-credentials", "true");
            Response.Headers.Append("access-control-allow-headers", "X-CSRF-TOKEN,Content-Type,Pragma,Cache-Control,Expires,X-Auth-Bearer-Token,ot-tracer-sampled,ot-tracer-spanid,ot-tracer-traceid");
            Response.Headers.Append("access-control-max-age", "600");
            Response.Headers.Append("strict-transport-security", "max-age=3600");
            Response.Cookies.Append(".ROBLOSECURITY", "=_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items._|" + token);
            Console.WriteLine("[" + DateTime.Now + "] " + "User " + info.username + " has signed up!");
            return Ok(new string(JsonConvert.SerializeObject(returnobject)));
        }
        [HttpPost("v2/login")]

        public IActionResult login(LoginInfo info)
        {
            Response.Headers.Remove("host");
            Response.ContentType = "application/json";
            Response.Headers.Append("host", "auth.roblox.com");
            Response.Headers.Append("cache-control", "no-cache");
            Response.Headers.Append("pragma", "no-cache");
            Response.Headers.Append("expires", "-1");
            Response.Headers.Append("vary", "Accept-Encoding");
            Response.Headers.Append("access-control-allow-origin", "https://www.roblox.com");
            Response.Headers.Append("access-control-allow-credentials", "true");
            Response.Headers.Append("x-frame-options", "SAMEORIGIN");
            Response.Headers.Append("strict-transport-security", "max-age=3600");
            Response.Headers.Append("roblox-machine-id", "CHI1-WEB3816");
            Response.Headers.Append("p3p", "CP=\"CAO DSP COR CURa ADMa DEVa OUR IND PHY ONL UNI COM NAV INT DEM PRE\"");
            Response.Headers.Append("report-to", "{\"group\":\"network-errors\",\"max_age\":604800,\"endpoints\":[{\"url\":\"https://ncs.roblox.com/upload\"}]}");
            Response.Headers.Append("nel", "{\"report_to\":\"network-errors\",\"max_age\":604800,\"success_fraction\":0.001,\"failure_fraction\":1}");
            // Response.Headers.Append("content-type", "application/json");

            string response = "";
            try
            {
                string token = Crypt.Crypt.GenerateUniqueHexString(778);
                var dbClient = new MongoClient("mongodb://127.0.0.1:27017");
                IMongoDatabase db = dbClient.GetDatabase("roblox");
                var users = db.GetCollection<BsonDocument>("users");
                try
                {
                    var @event = users.Find($"{{ username: '" + info.cvalue + $"' }}").Single();
                    UserInfo obj = BsonSerializer.Deserialize<UserInfo>(@event);

                    if (Crypt.Crypt.VerifyHashedPassword(obj.password, info.password))
                    {
                        Console.WriteLine("[" + DateTime.Now + "] " + "User " + obj.username + " has logged in!");
                        CookieOptions persistent = new CookieOptions();
                        persistent.Expires = DateTime.Now.AddDays(100);
                        Response.Headers.Append("set-cookie", ".ROBLOSECURITY=_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_" + token.ToUpper() + "; domain=.roblox.com; expires=Tue, 11-Jun-2052 18:05:00 GMT; path=/; secure; HttpOnly");
                        response = @"{""user"":{""id"":" + obj.userId + @",""name"":""" + obj.username + @""",""displayName"":""" + obj.displayName + @"""},""isBanned"":false}";
                        return new ObjectResult(response) { StatusCode = 200 } ;
                    }
                    else
                    {
                        Console.WriteLine("[" + DateTime.Now + "] " + "User " + obj.username + " has failed to log in!");
                        response = @"{""errors"":[{""code"":1,""message"":""Incorrect username or password. Please try again."",""userFacingMessage"":""Something went wrong""}]}";
                        return new ObjectResult(response) { StatusCode = 403 };
                    }
                }
                catch (Exception err)
                {
                    Console.WriteLine("[" + DateTime.Now + "] " + "User attempted to log in with invalid username!");
                    response = @"{""errors"":[{""code"":1,""message"":""Incorrect username or password. Please try again."",""userFacingMessage"":""Something went wrong""}]}";
                    return new ObjectResult(response) { StatusCode = 403 };
                }
            } catch (Exception err)
            {
                Console.WriteLine("[" + DateTime.Now + "] " + "User has triggered error:");
                Console.WriteLine(err);
                response = @"{""errors"":[{""code"":1,""message"":""Incorrect username or password. Please try again."",""userFacingMessage"":""Something went wrong""}]}";
                return new ObjectResult(response) { StatusCode = 403 };
            }
        }

        [HttpGet("v2/metadata")]

        public IActionResult MetaData()
        {
            Response.Headers.Append("access-control-allow-methods", "GET, PUT, POST, DELETE, HEAD");
            Response.Headers.Append("report-to", "{\"group\":\"network-errors\",\"max_age\":604800,\"endpoints\":[{\"url\":\"https://ncs.roblox.com/upload}]}");
            Response.Headers.Append("nel", "{\"report_to\":\"network-errors\",\"max_age\":604800,\"success_fraction\":0.001,\"failure_fraction\":1}");
            Response.Headers.Append("roblox-machine-id", "CHI1-WEB3816");
            Response.Headers.Append("p3p", "CP=\"CAO DSP COR CURa ADMa DEVa OUR IND PHY ONL UNI COM NAV INT DEM PRE\"");
            Response.Headers.Append("cache-control", "max-age=120, private");
            Response.Headers.Append("access-control-allow-origin", "https://www.roblox.com");
            Response.Headers.Append("access-control-allow-credentials", "true");
            Response.Headers.Append("access-control-allow-headers", "X-CSRF-TOKEN,Content-Type,Pragma,Cache-Control,Expires,X-Auth-Bearer-Token,ot-tracer-sampled,ot-tracer-spanid,ot-tracer-traceid");
            Response.Headers.Append("access-control-max-age", "600");
            Response.Headers.Append("strict-transport-security", "max-age=3600");
            return Ok();
        }

        [HttpOptions("v2/login")]
        
        public IActionResult loginOptions()
        {
            Response.Headers.Append("access-control-allow-methods", "GET, PUT, POST, DELETE, HEAD");
            Response.Headers.Append("report-to", "{\"group\":\"network-errors\",\"max_age\":604800,\"endpoints\":[{\"url\":\"https://ncs.roblox.com/upload}]}");
            Response.Headers.Append("nel", "{\"report_to\":\"network-errors\",\"max_age\":604800,\"success_fraction\":0.001,\"failure_fraction\":1}");
            Response.Headers.Append("roblox-machine-id", "CHI1-WEB3816");
            Response.Headers.Append("p3p", "CP=\"CAO DSP COR CURa ADMa DEVa OUR IND PHY ONL UNI COM NAV INT DEM PRE\"");
            Response.Headers.Append("cache-control", "max-age=120, private");
            Response.Headers.Append("access-control-allow-origin", "https://www.roblox.com");
            Response.Headers.Append("access-control-allow-credentials", "true");
            Response.Headers.Append("access-control-allow-headers", "X-CSRF-TOKEN,Content-Type,Pragma,Cache-Control,Expires,X-Auth-Bearer-Token,ot-tracer-sampled,ot-tracer-spanid,ot-tracer-traceid");
            Response.Headers.Append("access-control-max-age", "600");
            Response.Headers.Append("strict-transport-security", "max-age=3600");

            return Ok();
        }

        [HttpOptions("v2/signup")]

        public IActionResult signupOptions()
        {
            Response.Headers.Append("access-control-allow-methods", "GET, PUT, POST, DELETE, HEAD");
            Response.Headers.Append("report-to", "{\"group\":\"network-errors\",\"max_age\":604800,\"endpoints\":[{\"url\":\"https://ncs.roblox.com/upload}]}");
            Response.Headers.Append("nel", "{\"report_to\":\"network-errors\",\"max_age\":604800,\"success_fraction\":0.001,\"failure_fraction\":1}");
            Response.Headers.Append("roblox-machine-id", "CHI1-WEB3816");
            Response.Headers.Append("p3p", "CP=\"CAO DSP COR CURa ADMa DEVa OUR IND PHY ONL UNI COM NAV INT DEM PRE\"");
            Response.Headers.Append("cache-control", "max-age=120, private");
            Response.Headers.Append("access-control-allow-origin", "https://www.roblox.com");
            Response.Headers.Append("access-control-allow-credentials", "true");
            Response.Headers.Append("access-control-allow-headers", "X-CSRF-TOKEN,Content-Type,Pragma,Cache-Control,Expires,X-Auth-Bearer-Token,ot-tracer-sampled,ot-tracer-spanid,ot-tracer-traceid");
            Response.Headers.Append("access-control-max-age", "600");
            Response.Headers.Append("strict-transport-security", "max-age=3600");

            return Ok();
        }

        [HttpOptions("v1/usernames/validate")]

        public IActionResult usernamevalidateoptions()
        {
            Response.Headers.Append("report-to", "{\"group\":\"network-errors\",\"max_age\":604800,\"endpoints\":[{\"url\":\"https://ncs.roblox.com/upload}]}");
            Response.Headers.Append("nel", "{\"report_to\":\"network-errors\",\"max_age\":604800,\"success_fraction\":0.001,\"failure_fraction\":1}");
            Response.Headers.Append("roblox-machine-id", "CHI1-WEB3816");
            Response.Headers.Append("p3p", "CP=\"CAO DSP COR CURa ADMa DEVa OUR IND PHY ONL UNI COM NAV INT DEM PRE\"");
            Response.Headers.Append("access-control-allow-origin", "https://www.roblox.com");
            Response.Headers.Append("access-control-max-age", "600");
            Response.Headers.Append("access-control-allow-headers", "X-CSRF-TOKEN,Content-Type,Pragma,Cache-Control,Expires,X-Auth-Bearer-Token,ot-tracer-sampled,ot-tracer-spanid,ot-tracer-traceid");
            Response.Headers.Append("access-control-allow-methods", "OPTIONS, TRACE, GET, HEAD, POST, DELETE, PATCH");
            Response.Headers.Append("access-control-allow-credentials", "true");
            Response.Headers.Append("strict-transport-security", "max-age=3600");

            return Ok();
        }

        [HttpPost("v1/usernames/validate")]
        
        // i turned off the bad word filter simply because it doesn't
        // matter, though i did still want to implement it for future
        // use, in case anyone actually uses this as a backend and
        // hosts it for others (or if i host it myself for others)
        
        public IActionResult validateUsername(UsernameValidate info)
        {

            Response.Headers.Append("access-control-allow-methods", "GET, PUT, POST, DELETE, HEAD");
            Response.Headers.Append("report-to", "{\"group\":\"network-errors\",\"max_age\":604800,\"endpoints\":[{\"url\":\"https://ncs.roblox.com/upload}]}");
            Response.Headers.Append("nel", "{\"report_to\":\"network-errors\",\"max_age\":604800,\"success_fraction\":0.001,\"failure_fraction\":1}");
            Response.Headers.Append("roblox-machine-id", "CHI1-WEB3816");
            Response.Headers.Append("p3p", "CP=\"CAO DSP COR CURa ADMa DEVa OUR IND PHY ONL UNI COM NAV INT DEM PRE\"");
            Response.Headers.Append("cache-control", "max-age=120, private");
            Response.Headers.Append("access-control-allow-origin", "https://www.roblox.com");
            Response.Headers.Append("access-control-allow-credentials", "true");
            Response.Headers.Append("access-control-allow-headers", "X-CSRF-TOKEN,Content-Type,Pragma,Cache-Control,Expires,X-Auth-Bearer-Token,ot-tracer-sampled,ot-tracer-spanid,ot-tracer-traceid");
            Response.Headers.Append("access-control-max-age", "600");
            Response.Headers.Append("strict-transport-security", "max-age=3600");

            string response = "";
                var dbClient = new MongoClient("mongodb://127.0.0.1:27017");
                IMongoDatabase db = dbClient.GetDatabase("roblox");
                var users = db.GetCollection<BsonDocument>("users");
            try
            {
                var @event = users.Find($"{{ username: '" + info.username + $"' }}").Single();
                Console.WriteLine("[" + DateTime.Now + "] " + "Someone attempted to validate username " + info.username + "! (Already in use)");
                response = "{\"code\":1,\"message\":\"Username is already in use\"}";
            }
            catch
            {
            //    Regex wordFilter = new Regex("(2girls1cup|2g1c|4r5e|5h1t|5hit|a55|a_s_s|acrotomophilia|alabamahotpocket|alaskanpipeline|anal|anilingus|anus|apeshit|ar5e|arrse|arse|arsehole|ass|ass-fucker|ass-hat|ass-pirate|assbag|assbandit|assbanger|assbite|assclown|asscock|asscracker|asses|assface|assfucker|assfukka|assgoblin|asshat|asshead|asshole|assholes|asshopper|assjacker|asslick|asslicker|assmonkey|assmunch|assmuncher|asspirate|assshole|asssucker|asswad|asswhole|asswipe|autoerotic|autoerotic|b!tch|b00bs|b17ch|b1tch|babeland|babybatter|babyjuice|ballgag|ballgravy|ballkicking|balllicking|ballsack|ballsucking|ballbag|balls|ballsack|bampot|bangbros|bareback|barelylegal|barenaked|bastard|bastardo|bastinado|bbw|bdsm|beaner|beaners|beastial|beastiality|beastility|beavercleaver|beaverlips|bellend|bestial|bestiality|bi+ch|biatch|bigblack|bigbreasts|bigknockers|bigtits|bimbos|birdlock|bitch|bitcher|bitchers|bitches|bitchin|bitching|blackcock|blondeaction|blondeonblondeaction|bloody|blowjob|blowyourload|blowjob|blowjobs|bluewaffle|blumpkin|boiolas|bollock|bollocks|bollok|bollox|bondage|boner|boob|boobie|boobs|booobs|boooobs|booooobs|booooooobs|bootycall|breasts|brownshowers|brunetteaction|buceta|bugger|bukkake|bulldyke|bulletvibe|bullshit|bum|bunghole|bunghole|bunnyfucker|busty|butt|butt-pirate|buttcheeks|butthole|buttmunch|buttplug|c0ck|c0cksucker|cameltoe|camgirl|camslut|camwhore|carpetmuncher|carpetmuncher|cawk|chinc|chink|choad|chocolaterosebuds|chode|cipa|circlejerk|cl1t|clevelandsteamer|clit|clitface|clitoris|clits|cloverclamps|clusterfuck|cnut|cock|cock-sucker|cockbite|cockburger|cockface|cockhead|cockjockey|cockknoker|cockmaster|cockmongler|cockmongruel|cockmonkey|cockmunch|cockmuncher|cocknose|cocknugget|cocks|cockshit|cocksmith|cocksmoker|cocksuck|cocksuck|cocksucked|cocksucked|cocksucker|cocksucking|cocksucks|cocksuka|cocksukka|cok|cokmuncher|coksucka|coochie|coochy|coon|coons|cooter|coprolagnia|coprophilia|cornhole|cox|crap|creampie|cum|cumbubble|cumdumpster|cumguzzler|cumjockey|cummer|cumming|cums|cumshot|cumslut|cumtart|cunilingus|cunillingus|cunnie|cunnilingus|cunt|cuntface|cunthole|cuntlick|cuntlick|cuntlicker|cuntlicker|cuntlicking|cuntlicking|cuntrag|cunts|cyalis|cyberfuc|cyberfuck|cyberfucked|cyberfucker|cyberfuckers|cyberfucking|d1ck|dammit|damn|darkie|daterape|daterape|deepthroat|deepthroat|dendrophilia|dick|dickbag|dickbeater|dickface|dickhead|dickhole|dickjuice|dickmilk|dickmonger|dickslap|dicksucker|dickwad|dickweasel|dickweed|dickwod|dike|dildo|dildos|dingleberries|dingleberry|dink|dinks|dipshit|dirsa|dirtypillows|dirtysanchez|dlck|dogstyle|dog-fucker|doggiestyle|doggiestyle|doggin|dogging|doggystyle|doggystyle|dolcett|domination|dominatrix|dommes|donkeypunch|donkeyribber|doochbag|dookie|doosh|doubledong|doublepenetration|douche|douchebag|dpaction|dryhump|duche|dumbshit|dumshit|dvda|dyke|eatmyass|ecchi|ejaculate|ejaculated|ejaculates|ejaculating|ejaculatings|ejaculation|ejakulate|erotic|erotism|escort|eunuch|fuck|Fuck|fucker|f4nny|f_u_c_k|fag|fagbag|fagg|fagging|faggit|faggitt|faggot|faggs|fagot|fagots|fags|fagtard|fanny|fannyflaps|fannyfucker|fanyy|fart|farted|farting|farty|fatass|fcuk|fcuker|fcuking|fecal|feck|fecker|felatio|felch|felching|fellate|fellatio|feltch|femalesquirting|femdom|figging|fingerbang|fingerfuck|fingerfucked|fingerfucker|fingerfuckers|fingerfucking|fingerfucks|fingering|fistfuck|fistfucked|fistfucker|fistfuckers|fistfucking|fistfuckings|fistfucks|fisting|flamer|flange|fook|fooker|footfetish|footjob|frotting|fuck|fuckbuttons|fucka|fucked|fucker|fuckers|fuckhead|fuckheads|fuckin|fucking|fuckings|fuckingshitmotherfucker|fuckme|fucks|fucktards|fuckwhit|fuckwit|fudgepacker|fudgepacker|fuk|fuker|fukker|fukkin|fuks|fukwhit|fukwit|futanari|fux|fux0r|g-spot|gangbang|gangbang|gangbanged|gangbanged|gangbangs|gaysex|gayass|gaybob|gaydo|gaylord|gaysex|gaytard|gaywad|genitals|giantcock|girlon|girlontop|girlsgonewild|goatcx|goatse|goddamn|god-dam|god-damned|goddamn|goddamned|gokkun|goldenshower|googirl|gooch|goodpoop|gook|goregasm|gringo|grope|groupsex|guido|guro|handjob|handjob|hardcore|hardcore|hardcoresex|heeb|hentai|heshe|ho|hoar|hoare|hoe|hoer|homo|homoerotic|honkey|honky|hooker|hore|horniest|horny|hotcarl|hotchick|hotsex|howtokill|howtomurder|hugefat|humping|incest|intercourse|jackoff|jack-off|jackass|jackoff|jailbait|jailbait|jap|jellydonut|jerkoff|jerk-off|jigaboo|jiggaboo|jiggerboo|jism|jiz|jiz|jizm|jizm|jizz|juggs|kawk|kike|kinbaku|kinkster|kinky|kiunt|knob|knobbing|knobead|knobed|knobend|knobhead|knobjocky|knobjokey|kock|kondum|kondums|kooch|kootch|kum|kumer|kummer|kumming|kums|kunilingus|kunt|kyke|l3i+ch|l3itch|labia|leatherrestraint|leatherstraightjacket|lemonparty|lesbo|lezzie|lmfao|lolita|lovemaking|lust|lusting|m0f0|m0fo|m45terbate|ma5terb8|ma5terbate|makemecome|malesquirting|masochist|master-bate|masterb8|masterbat*|masterbat3|masterbate|masterbation|masterbations|masturbate|menageatrois|milf|minge|missionaryposition|mo-fo|mof0|mofo|mothafuck|mothafucka|mothafuckas|mothafuckaz|mothafucked|mothafucker|mothafuckers|mothafuckin|mothafucking|mothafuckings|mothafucks|motherfucker|motherfuck|motherfucked|motherfucker|motherfuckers|motherfuckin|motherfucking|motherfuckings|motherfuckka|motherfucks|moundofvenus|mrhands|muff|muffdiver|muffdiver|muffdiving|mutha|muthafecker|muthafuckker|muther|mutherfucker|n1gga|n1gger|nambla|nawashi|nazi|negro|neonazi|nignog|nigg3r|nigg4h|nigga|niggah|niggas|niggaz|nigger|niggers|niglet|nimphomania|nipple|nipples|nob|nobjokey|nobhead|nobjocky|nobjokey|nsfwimages|nude|nudity|numbnuts|nutsack|nympho|nymphomania|octopussy|omorashi|onecuptwogirls|oneguyonejar|orgasim|orgasim|orgasims|orgasm|orgasms|orgy|p0rn|paedophile|paki|panooch|panties|panty|pawn|pecker|peckerhead|pedobear|pedophile|pegging|penis|penisfucker|phonesex|phonesex|phuck|phuk|phuked|phuking|phukked|phukking|phuks|phuq|pieceofshit|pigfucker|pimpis|pis|pises|pisin|pising|pisof|piss|pisspig|pissed|pisser|pissers|pisses|pissflap|pissflaps|pissin|pissin|pissing|pissoff|pissoff|pisspig|playboy|pleasurechest|polesmoker|polesmoker|pollock|ponyplay|poo|poof|poon|poonani|poonany|poontang|poop|poopchute|poopchute|porn|porno|pornography|pornos|prick|pricks|princealbertpiercing|pron|pthc|pube|pubes|punanny|punany|punta|pusies|pusse|pussi|pussies|pussy|pussylicking|pussys|pusy|puto|queaf|queef|queerbait|queerhole|quim|raghead|ragingboner|rape|raping|rapist|rectum|renob|retard|reversecowgirl|rimjaw|rimjob|rimming|rosypalm|rosypalmandher5sisters|ruski|rustytrombone|shit|s&m|s.o.b.|s_h_i_t|sadism|sadist|santorum|scat|schlong|scissoring|screwing|scroat|scrote|scrotum|semen|sex|sexo|sexy|sh!+|sh!t|sh1t|shag|shagger|shaggin|shagging|shavedbeaver|shavedpussy|shemale|shi+|shibari|shit|shit-ass|shit-bag|shit-bagger|shit-brain|shit-breath|shit-cunt|shit-dick|shit-eating|shit-face|shit-faced|shit-fit|shit-head|shit-heel|shit-hole|shit-house|shit-load|shit-pot|shit-spitter|shit-stain|shitass|shitbag|shitbagger|shitblimp|shitbrain|shitbreath|shitcunt|shitdick|shite|shiteating|shited|shitey|shitface|shitfaced|shitfit|shitfuck|shitfull|shithead|shitheel|shithole|shithouse|shiting|shitings|shitload|shitpot|shits|shitspitter|shitstain|shitted|shitter|shitters|shittiest|shitting|shittings|shitty|shitty|shity|shiz|shiznit|shota|shrimping|skank|skeet|slanteye|slut|slutbag|sluts|smeg|smegma|smut|snatch|snowballing|sodomize|sodomy|son-of-a-bitch|spac|spic|spick|splooge|sploogemoose|spooge|spreadlegs|spunk|strapon|strapon|strappado|stripclub|styledoggy|suck|sucks|suicidegirls|sultrywomen|swastika|swinger|t1tt1e5|t1tties|taintedlove|tard|tastemy|teabagging|teets|teez|testical|testicle|threesome|throating|thundercunt|tiedup|tightwhite|tit|titfuck|tits|titt|tittie5|tittiefucker|titties|titty|tittyfuck|tittywank|titwank|tongueina|topless|tosser|towelhead|tranny|tribadism|tubgirl|tubgirl|turd|tushy|tw4t|twat|twathead|twatlips|twatty|twink|twinkie|twogirlsonecup|twunt|twunter|undressing|upskirt|urethraplay|urophilia|v14gra|v1gra|va-j-j|vag|vagina|venusmound|viagra|vibrator|violetwand|vjayjay|vorarephilia|voyeur|vulva|w00se|wang|wank|wanker|wanky|wetdream|wetback|whitepower|whoar|whore|willies|willy|wrappingmen|wrinkledstarfish|xrated|xx|xxx|yaoi|yellowshowers|yiffy|zoophilia)", RegexOptions.IgnoreCase);
            //    if (wordFilter.IsMatch(info.username))
            //    {
            //        response = "{\"code\":2,\"message\":\"Username is not appropriate for RopenAPI\"}";
            //        Console.WriteLine("[" + DateTime.Now + "] " + "Someone attempted to validate username " + info.username + "! (Contains bad word)");
            //    }
            //    else
            //    {
                    response = "{\"code\":0,\"message\":\"Username is valid\"}";
                    Console.WriteLine("[" + DateTime.Now + "] " + "Someone attempted to validate username " + info.username + "! (Successful)");
            //    }

            }
            return new ObjectResult(response) { StatusCode = 200 };
        }

    }

    public class UsernameValidate
    {
        public string birthday { get; set; }
        public string context { get; set; }
        public string username { get; set; }

    }

    public class UserInfo
    {
        public ObjectId _id = new ObjectId();
        public List<string> agreementIds = new List<string>();
        public string birthday { get; set; }

        public string context { get; set; }

        public int gender { get; set; }

        public bool isTosAgreementBoxChecked { get; set; }

        public string password { get; set; }

        public string username { get; set; }

        public string starterPlaceId = "";

        public string displayName = "";

        public string userId = "";

        public string token = "";

    }

    public class LoginInfo
    {
        public ObjectId _id = new ObjectId();

        public string ctype = "Username";
        public string cvalue { get; set; }
        public string password { get; set; }

    }


}