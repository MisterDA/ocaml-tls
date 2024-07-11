open Lwt
open Ex_common

let mypsk = ref None

let ticket_cache = {
  Tls.Config.lookup = (fun _ -> None) ;
  ticket_granted = (fun psk epoch -> mypsk := Some (psk, epoch)) ;
  lifetime = 0l ;
  timestamp = Ptime_clock.now
}

let resolve host service =
  let open Lwt_unix in
  getprotobyname "tcp" >>= fun tcp ->
  getaddrinfo host service [AI_PROTOCOL tcp.p_proto] >>= function
  | []    ->
      let msg = Printf.sprintf "no address for %s:%s" host service in
      Lwt.reraise (Invalid_argument msg)
  | ai::_ -> Lwt.return ai.ai_addr

let tcp_connect (host, port) =
  let open Lwt.Infix in
    resolve host (string_of_int port) >>= fun addr ->
    let fd = Lwt_unix.(socket (Unix.domain_of_sockaddr addr) SOCK_STREAM 0) in
    Lwt.catch (fun () ->
      let _host =
        Result.to_option
          (Result.bind (Domain_name.of_string host) Domain_name.host)
      in
      Lwt_unix.connect fd addr >|= fun () -> fd)
      (function
        | Out_of_memory -> raise Out_of_memory
        | exn -> (Lwt_unix.close fd) >>= fun () -> Lwt.reraise exn)

let test_client _ =
(*  X509_lwt.private_of_pems
    ~cert:server_cert
    ~priv_key:server_key >>= fun cert -> *)
  let port = 18080 in
  let proxy = "178.48.68.61" in
  let hostname = "sherlocode.com" in
  (* let proxy = "127.0.0.1" in *)
  let authenticator = null_auth in
  let client = Tls.Config.(client ~version:(`TLS_1_0, `TLS_1_3) (* ~certificates:(`Single cert) *) ?cached_ticket:!mypsk ~ticket_cache ~authenticator ~ciphers:Ciphers.supported ()) in

  tcp_connect (proxy, port) >>= fun fd ->
  let ic = Lwt_io.of_fd ~mode:Input fd in
  let oc = Lwt_io.of_fd ~mode:Output fd in
  let req = String.concat "\r\n" [
    "CONNECT " ^ hostname ^ ":443 HTTP/1.1" ; "Host: " ^ hostname ; "" ; ""
  ] in
  Lwt_io.write oc req >>= fun () ->

  let expect1 = "HTTP/1.1 200 OK\r\n\r\n" in
  let expect2 = "HTTP/1.1 200 Connection established\r\n\r\n" in
  Lwt_io.read ~count:(String.length expect2) ic >>= fun ok ->
  assert (List.mem ok [expect1;expect2]);

  let host = Result.get_ok (Domain_name.of_string hostname) in
  let host = Result.get_ok (Domain_name.host host) in

  Tls_lwt.Unix.client_of_channels client ~host (ic, oc) >>= fun t ->
  let (ic, oc) = Tls_lwt.of_t t in
  let req = String.concat "\r\n" [
    "GET / HTTP/1.1" ; "Host: " ^ hostname ; "" ; ""
  ] in

  Lwt_io.(write oc req >>= fun () ->
          read ~count:12000 ic >>= print >>= fun () ->
          close oc >>= fun () ->
          printf "++ done.\n%!")

let jump _ =
  try
    Lwt_main.run (test_client ()) ; `Ok ()
  with
  | Tls_lwt.Tls_alert alert as exn ->
      print_alert "remote end" alert ; raise exn
  | Tls_lwt.Tls_failure alert as exn ->
      print_fail "our end" alert ; raise exn

open Cmdliner

let cmd =
  let term = Term.(ret (const jump $ setup_log))
  and info = Cmd.info "test_client" ~version:"%%VERSION_NUM%%"
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
