sudo ./scion.sh topology -c topology/freestanding.topo -n 10.0.0.0/8

for i in {1..5}
do
	pushd gen/ASffaa_1_$i/
	mv br*.toml br.toml 
	sed -i 's/^config_dir = ".*"$/config_dir = "\/etc\/scion"/g' br.toml	
	sed -i '/\[metrics\]/{N;N;d}' br.toml	
	sed -i '/\[api\]/{N;N;d}' br.toml	#use api from topology.json
	
	mv cs*.toml cs.toml 
	sed -i 's/^config_dir = ".*"$/config_dir = "\/etc\/scion"/g' cs.toml	
	sed -i 's/^connection = ".*\.trust\.db"$/connection = "\/var\/lib\/scion\/control.trust.db"/g' cs.toml	
	sed -i 's/^connection = ".*\.beacon\.db"$/connection = "\/var\/lib\/scion\/control.beacon.db"/g' cs.toml	
	sed -i 's/^connection = ".*\.path\.db"$/connection = "\/var\/lib\/scion\/control.path.db"/g' cs.toml	
	sed -i '/\[metrics\]/{N;N;d}' cs.toml	
	sed -i '/\[tracing\]/{N;N;N;N;d}' cs.toml	
	sed -i '/\[api\]/{N;N;d}' cs.toml	#use api from topology.json

	rm -r prometheus
	rm prometheus.yml

	rm sd.toml			#using the default /etc/scion/deamon.toml

	jq '.control_service[] |= (.addr = "127.0.0.1:31001")' topology.json | sponge topology.json
	jq '.discovery_service[] |= (.addr = "127.0.0.1:31001")' topology.json | sponge topology.json
	jq '.border_routers[] |= (.internal_addr = "127.0.0.1:31002")' topology.json | sponge topology.json

	# set the ip addresses accordingly
	jq --arg l $i '.border_routers[].interfaces |= (
  with_entries(
    .value |= (
      (.isd_as | split(":")[-1] | tonumber) as $r
      | ([($l|tonumber|tostring), ($r|tostring)] | sort | join("")) as $n
      | .underlay.local  = "10.0.\($n).\($l):50000"
      | .underlay.remote = "10.0.\($n).\($r):50000"
    )
  )
)' topology.json | sponge topology.json

	popd

	rm -r lab-autogen-freestanding/scion0$i/etc/scion
	cp -R gen/ASffaa_1_$i/ lab-autogen-freestanding/scion0$i/etc/scion
done

