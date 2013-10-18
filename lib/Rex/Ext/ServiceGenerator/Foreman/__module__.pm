#
# (c) Jan Gehring <jan.gehring@gmail.com>
# 
# vim: set ts=3 sw=3 tw=0:
# vim: set expandtab:
   
package Rex::Ext::ServiceGenerator::Foreman;

use strict;
use warnings;

use Rex -base;
use YAML::Perl::Parser;
use YAML::Perl::Events;
use Data::Dumper;
use IO::All;

require Exporter;
use base qw(Exporter);
use vars qw (@EXPORT);


@EXPORT = qw(execute_service);

sub execute_service {
   my $server = connection->server;
   my $config = get "service_generator";

   my $content = io($config->{path} . "/" . $server . ".yml")->slurp;
   $content .= "\n";

   my $parser = YAML::Perl::Parser->new;
   $parser->open($content);

   my @classes;

   my $doc = [];

   $doc = parse_map($parser);

   _generate_class_module_mapping($doc->[0]->get("classes"));
}

sub _generate_class_module_mapping {
   my ($map) = @_;

   $map->each_key(sub {
      my ($key, $val) = @_;

      my $data;
      if(ref $val) {
         $data = $val->get_data;
      }

      my $module_name = "module::$key";
      my $module_name_task = "module::${key}::setup";

      include $module_name;
      no strict 'refs';
      &$module_name_task($data);
   });
}


# special yaml parser, to preserve ordering
sub parse_map {
   my ($parser) = @_;

   my ($key, $val);

   my $doc;

   while(my $event = $parser->parse()) {
      if(ref $event eq "YAML::Perl::Event::Scalar") {
         push @{ $doc }, $event->value;
      }
      elsif(ref $event eq "YAML::Perl::Event::MappingStart") {
         my @arr = @{ parse_map($parser) };
         #my %hash = @arr;
         my $hm = Rex::Ext::ServiceGenerator::Foreman::HashMap->new();
         $hm->add(@arr);
         push @{ $doc }, $hm;
      }
      elsif(ref $event eq "YAML::Perl::Event::SequenceStart") {
         push @{ $doc }, parse_map($parser);
      }

      if(ref $event eq "YAML::Perl::Event::MappingEnd" || ref $event eq "YAML::Perl::Event::SequenceEnd") {
         return $doc;
      }
   }

   return $doc;
}


1;

# to preseve the ordering...
package Rex::Ext::ServiceGenerator::Foreman::HashMap;

use strict;
use warnings;

sub new {
   my $that = shift;
   my $proto = ref($that) || $that;
   my $self = { @_ };

   bless($self, $proto);

   $self->{__keys__} = [];

   return $self;
}

sub add {
   my ($self, @vals) = @_;

   for(my $i=0; $i < scalar(@vals); $i+=2) {
      push @{ $self->{__keys__} }, { $vals[$i], $vals[$i+1] };
   }
}

sub get {
   my ($self, $key) = @_;

   for my $d (@{ $self->{__keys__} }) {
      my ($k) = keys %{ $d };
      if($k eq $key) {
         return $d->{$k};
      }
   }
}

sub each_key {
   my ($self, $code) = @_;

   for my $d (@{ $self->{__keys__} }) {
      my ($k) = each %{ $d };
      &$code($k, $d->{$k});
   }
}

sub get_data {
   my ($self) = @_;

   my $ret;
   for my $d (@{ $self->{__keys__} }) {
      my ($key) = keys %{ $d };
      $ret->{$key} = $d->{$key};
   }

   return $ret;
}

1;




__END__

---
classes:
    common:
    puppet:
    ntp:
        ntpserver: 0.pool.ntp.org
    aptsetup:
        additional_apt_repos:
            - deb localrepo.example.com/ubuntu lucid production
            - deb localrepo.example.com/ubuntu lucid vendor
parameters:
    ntp_servers:
        - 0.pool.ntp.org
        - ntp.example.com
    mail_server: mail.example.com
    iburst: true
environment: production






>> YAML::Perl::Event::StreamStart()
>> YAML::Perl::Event::DocumentStart()
>> YAML::Perl::Event::MappingStart(anchor=, tag=, implicit=1)
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a453dd0), value=classes)
classes
>> YAML::Perl::Event::MappingStart(anchor=, tag=, implicit=1)
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a490d60), value=common)
common
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a496d80), value=)

>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a4539c8), value=ntp)
ntp
>> YAML::Perl::Event::MappingStart(anchor=, tag=, implicit=1)
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a496e10), value=ntpserver)
ntpserver
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a4533b0), value=0.pool.ntp.org)
0.pool.ntp.org
>> YAML::Perl::Event::MappingEnd()
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a490d60), value=apt)
apt
>> YAML::Perl::Event::MappingStart(anchor=, tag=, implicit=1)
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a496e10), value=additional_apt_repos)
additional_apt_repos
>> YAML::Perl::Event::SequenceStart(anchor=, tag=, implicit=1)
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a496e28), value=deb localrepo.example.com/ubuntu lucid production)
deb localrepo.example.com/ubuntu lucid production
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a453668), value=deb localrepo.example.com/ubuntu lucid vendor)
deb localrepo.example.com/ubuntu lucid vendor
>> YAML::Perl::Event::SequenceEnd()
>> YAML::Perl::Event::MappingEnd()
>> YAML::Perl::Event::MappingEnd()
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a453950), value=parameters)
parameters
>> YAML::Perl::Event::MappingStart(anchor=, tag=, implicit=1)
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a496dc8), value=ntp_servers)
ntp_servers
>> YAML::Perl::Event::SequenceStart(anchor=, tag=, implicit=1)
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a4540a0), value=0.pool.ntp.org)
0.pool.ntp.org
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a497008), value=ntp.example.com)
ntp.example.com
>> YAML::Perl::Event::SequenceEnd()
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a496d80), value=mail_server)
mail_server
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a453320), value=mail.example.com)
mail.example.com
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a497398), value=iburst)
iburst
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a496c90), value=true)
true
>> YAML::Perl::Event::MappingEnd()
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a4539c8), value=environment)
environment
>> YAML::Perl::Event::Scalar(anchor=, tag=, implicit=ARRAY(0x7fc36a496d68), value=production)
production
>> YAML::Perl::Event::MappingEnd()
>> YAML::Perl::Event::DocumentEnd()
>> YAML::Perl::Event::StreamEnd()
